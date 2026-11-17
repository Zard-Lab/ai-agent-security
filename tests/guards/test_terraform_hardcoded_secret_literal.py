from __future__ import annotations

from agentsec.guards.terraform_hardcoded_secret_literal import TerraformHardcodedSecretLiteralGuard
from tests.guards._common import *  # noqa: F401,F403


def test_terraform_hardcoded_secret_literal_flags_resource_password(tmp_path: Path) -> None:
    (tmp_path / "db.tf").write_text(
        'resource "aws_db_instance" "app" {\n'
        '  engine   = "postgres"\n'
        '  password = "hunter2CHANGE"\n'
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    findings = TerraformHardcodedSecretLiteralGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "terraform-hardcoded-secret-literal/attribute-literal"
    assert findings[0].severity == "high"


def test_terraform_hardcoded_secret_literal_flags_provider_secret_key(tmp_path: Path) -> None:
    (tmp_path / "provider.tf").write_text(
        'provider "aws" {\n'
        '  access_key = "AKIAIOSFODNN7EXAMPLE"\n'
        '  secret_key = "wJalrXUtnFEMI1234567890abcdef"\n'
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    findings = TerraformHardcodedSecretLiteralGuard().run(tmp_path, profile)
    # Both access_key and secret_key are credential-shaped attributes -> two findings.
    assert len(findings) == 2
    assert {f.rule for f in findings} == {"terraform-hardcoded-secret-literal/attribute-literal"}


def test_terraform_hardcoded_secret_literal_fires_after_provider_heredoc(tmp_path: Path) -> None:
    # Regression (M3): a heredoc body with an unbalanced `}` inside a provider block must not
    # close the block early. The shared heredoc-aware walker keeps the `secret_key` below it in
    # scope (the old hand-rolled brace counter dropped it -> false negative).
    (tmp_path / "provider.tf").write_text(
        'provider "aws" {\n'
        "  policy = <<EOF\n"
        "some json body with a stray brace }\n"
        "EOF\n"
        '  secret_key = "wJalrXUtnFEMI1234567890abcdef"\n'
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    findings = TerraformHardcodedSecretLiteralGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "terraform-hardcoded-secret-literal/attribute-literal"


def test_terraform_hardcoded_secret_literal_silent_on_variable_reference(tmp_path: Path) -> None:
    (tmp_path / "db.tf").write_text(
        'resource "aws_db_instance" "app" {\n'
        "  password = var.db_password\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    assert TerraformHardcodedSecretLiteralGuard().run(tmp_path, profile) == []


def test_terraform_hardcoded_secret_literal_silent_on_data_source_reference(tmp_path: Path) -> None:
    (tmp_path / "db.tf").write_text(
        'resource "aws_db_instance" "app" {\n'
        "  secret_key = data.aws_secretsmanager_secret_version.x.secret_string\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    assert TerraformHardcodedSecretLiteralGuard().run(tmp_path, profile) == []


def test_terraform_hardcoded_secret_literal_silent_on_comment(tmp_path: Path) -> None:
    (tmp_path / "db.tf").write_text(
        'resource "aws_db_instance" "app" {\n'
        '  # password = "example12345"\n'
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    assert TerraformHardcodedSecretLiteralGuard().run(tmp_path, profile) == []


def test_terraform_hardcoded_secret_literal_silent_below_length_threshold(tmp_path: Path) -> None:
    (tmp_path / "db.tf").write_text(
        'resource "aws_db_instance" "app" {\n'
        '  password = "abcd"\n'  # a short placeholder, below the 8-char threshold
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    assert TerraformHardcodedSecretLiteralGuard().run(tmp_path, profile) == []


def test_terraform_hardcoded_secret_literal_silent_on_unrelated_attribute_name(tmp_path: Path) -> None:
    (tmp_path / "db.tf").write_text(
        'resource "aws_db_instance" "app" {\n'
        '  password_hash_algorithm = "bcrypt12"\n'  # config knob, not a credential value
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    assert TerraformHardcodedSecretLiteralGuard().run(tmp_path, profile) == []


def test_terraform_hardcoded_secret_literal_pragma_silences(tmp_path: Path) -> None:
    (tmp_path / "db.tf").write_text(
        'resource "aws_db_instance" "app" {\n'
        '  password = "SuperSecret123"  # security: allow-tf-hardcoded-secret\n'
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    assert TerraformHardcodedSecretLiteralGuard().run(tmp_path, profile) == []


def test_terraform_hardcoded_secret_literal_flags_variable_default_object_literal(tmp_path: Path) -> None:
    # a `variable` block was previously unwalked entirely. Realistic shape: the
    # `default` is an OBJECT and the credential-shaped key sits on its own line inside it.
    (tmp_path / "vars.tf").write_text(
        'variable "db_config" {\n'
        "  default = {\n"
        '    password = "SuperSecretPass123"\n'
        "  }\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    findings = TerraformHardcodedSecretLiteralGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "terraform-hardcoded-secret-literal/variable-default-literal"
    assert findings[0].severity == "high"


def test_terraform_hardcoded_secret_literal_silent_on_variable_with_no_default(tmp_path: Path) -> None:
    # FP bait (widening direction): a `variable` block with no `default` at all must stay silent.
    (tmp_path / "vars.tf").write_text(
        'variable "db_password" {\n'
        "  type        = string\n"
        '  description = "the database password, injected via TF_VAR_db_password"\n'
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    assert TerraformHardcodedSecretLiteralGuard().run(tmp_path, profile) == []


def test_terraform_hardcoded_secret_literal_flags_locals_literal(tmp_path: Path) -> None:
    # a `locals` block was previously unwalked entirely.
    (tmp_path / "locals.tf").write_text(
        "locals {\n"
        '  environment = "production"\n'
        '  secret      = "SuperSecretLocal123"\n'
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    findings = TerraformHardcodedSecretLiteralGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "terraform-hardcoded-secret-literal/locals-literal"
    assert findings[0].severity == "high"


def test_terraform_hardcoded_secret_literal_silent_on_locals_non_secret_key(tmp_path: Path) -> None:
    # FP bait: a `locals` block whose keys are ordinary config, not credential-named, stays silent.
    (tmp_path / "locals.tf").write_text(
        "locals {\n"
        '  environment = "production"\n'
        '  region      = "us-east-1"\n'
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    assert TerraformHardcodedSecretLiteralGuard().run(tmp_path, profile) == []


def test_terraform_hardcoded_secret_literal_flags_output_value_literal(tmp_path: Path) -> None:
    # an `output` block was previously unwalked entirely.
    (tmp_path / "outputs.tf").write_text(
        'output "db_connection" {\n'
        "  value = {\n"
        '    password = "SuperSecretOutput123"\n'
        "  }\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    findings = TerraformHardcodedSecretLiteralGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "terraform-hardcoded-secret-literal/output-literal"
    assert findings[0].severity == "high"


def test_terraform_hardcoded_secret_literal_silent_on_output_variable_reference(tmp_path: Path) -> None:
    # FP bait: an `output` whose value is a reference (not a literal) stays silent.
    (tmp_path / "outputs.tf").write_text(
        'output "db_host" {\n'
        "  value = aws_db_instance.app.address\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    assert TerraformHardcodedSecretLiteralGuard().run(tmp_path, profile) == []


def test_terraform_hardcoded_secret_literal_flags_akia_in_user_data_heredoc(tmp_path: Path) -> None:
    # a credential embedded INSIDE a user_data heredoc blob, invisible to the
    # attribute-literal regex (which expects `attr = "literal"`, not a literal buried in a
    # larger multi-line string).
    (tmp_path / "instance.tf").write_text(
        'resource "aws_instance" "app" {\n'
        '  ami           = "ami-0abcdef1234567890"\n'
        '  instance_type = "t3.micro"\n'
        "  user_data = <<-EOF\n"
        "    #!/bin/bash\n"
        "    export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n"
        "    EOF\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    findings = TerraformHardcodedSecretLiteralGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "terraform-hardcoded-secret-literal/user-data-embedded-secret"
    assert findings[0].severity == "high"
    assert "AKIA" in findings[0].message


def test_terraform_hardcoded_secret_literal_flags_password_in_user_data_heredoc(tmp_path: Path) -> None:
    # the non-AKIA path: a credential-word token (`password=`) embedded in the blob.
    (tmp_path / "instance.tf").write_text(
        'resource "aws_instance" "app" {\n'
        "  user_data = <<-EOF\n"
        "    #!/bin/bash\n"
        '    echo "configuring app"\n'
        "    password=SuperSecretBoot123\n"
        "    EOF\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    findings = TerraformHardcodedSecretLiteralGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "terraform-hardcoded-secret-literal/user-data-embedded-secret"


def test_terraform_hardcoded_secret_literal_flags_akia_in_user_data_one_liner(tmp_path: Path) -> None:
    # the non-heredoc path: a plain one-line quoted `user_data` string.
    (tmp_path / "instance.tf").write_text(
        'resource "aws_instance" "app" {\n'
        '  user_data = "export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE"\n'
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    findings = TerraformHardcodedSecretLiteralGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "terraform-hardcoded-secret-literal/user-data-embedded-secret"


def test_terraform_hardcoded_secret_literal_silent_on_benign_user_data(tmp_path: Path) -> None:
    # FP bait (widening direction): a user_data blob with no embedded credential shape stays silent.
    (tmp_path / "instance.tf").write_text(
        'resource "aws_instance" "app" {\n'
        "  user_data = <<-EOF\n"
        "    #!/bin/bash\n"
        "    apt-get update && apt-get install -y nginx\n"
        '    echo "deployment complete"\n'
        "    EOF\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    assert TerraformHardcodedSecretLiteralGuard().run(tmp_path, profile) == []


def test_terraform_hardcoded_secret_literal_silent_on_commented_akia_in_heredoc(tmp_path: Path) -> None:
    # Real FP found by review: `_scan_blob` didn't skip `#` comments the way `_scan_body` does,
    # so AWS's own canonical documentation placeholder sitting in a genuine comment fired HIGH.
    (tmp_path / "instance.tf").write_text(
        'resource "aws_instance" "app" {\n'
        "  user_data = <<-EOF\n"
        "    #!/bin/bash\n"
        "    # example only, see docs: AKIAIOSFODNN7EXAMPLE\n"
        '    echo "hi"\n'
        "    EOF\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    assert TerraformHardcodedSecretLiteralGuard().run(tmp_path, profile) == []


def test_terraform_hardcoded_secret_literal_still_fires_on_uncommented_akia_in_heredoc(tmp_path: Path) -> None:
    # Narrowing-still-fires control for the comment-skip fix above: a genuine, uncommented AKIA
    # content line in the SAME heredoc must still fire — the comment skip must not swallow real
    # findings, only comment-only lines.
    (tmp_path / "instance.tf").write_text(
        'resource "aws_instance" "app" {\n'
        "  user_data = <<-EOF\n"
        "    #!/bin/bash\n"
        "    # example only, see docs: AKIAIOSFODNN7EXAMPLE\n"
        "    export AWS_ACCESS_KEY_ID=AKIAI44QH8DHBEXAMPLE\n"
        "    EOF\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    findings = TerraformHardcodedSecretLiteralGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "terraform-hardcoded-secret-literal/user-data-embedded-secret"
    # detection still fires on the real key, but the finding message must never carry
    # the full matched secret literal verbatim — only a redacted prefix+last4 form.
    assert "AKIAI44QH8DHBEXAMPLE" not in findings[0].message
    assert "AKIA...MPLE" in findings[0].message


def test_terraform_hardcoded_secret_literal_akia_message_redacts_full_key(tmp_path: Path) -> None:
    # regression: `_scan_blob`'s AKIA branch used to echo the full 20-char matched AWS
    # access key literal into `Finding.message` verbatim (`f"an AWS access key (`{akia.group(0)}`)"`),
    # unlike its `_CRED_CONTENT` sibling branch which redacts to `name=...`. A real secret value
    # must never land in a committed report, PR body, or shared wiki page. This asserts the exact
    # raw matched key text is absent from the message, while detection (the finding itself, at the
    # correct rule/severity) is unaffected.
    test_key = "AKIAT7EXAMPLEKEY9999"
    (tmp_path / "instance.tf").write_text(
        'resource "aws_instance" "app" {\n'
        "  user_data = <<-EOF\n"
        "    #!/bin/bash\n"
        f"    export AWS_ACCESS_KEY_ID={test_key}\n"
        "    EOF\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    findings = TerraformHardcodedSecretLiteralGuard().run(tmp_path, profile)
    # Detection still fires, unaffected — only the message text changes.
    assert len(findings) == 1
    assert findings[0].rule == "terraform-hardcoded-secret-literal/user-data-embedded-secret"
    assert findings[0].severity == "high"
    # The full raw matched key must never appear in the finding message.
    assert test_key not in findings[0].message
    # A redacted form (prefix + last 4 chars) is still present so the finding remains actionable.
    assert "AKIA..." in findings[0].message
    assert test_key[-4:] in findings[0].message


def test_terraform_hardcoded_secret_literal_user_data_pragma_silences(tmp_path: Path) -> None:
    (tmp_path / "instance.tf").write_text(
        'resource "aws_instance" "app" {\n'
        "  user_data = <<-EOF\n"
        "    export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE  # security: allow-tf-hardcoded-secret\n"
        "    EOF\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    assert TerraformHardcodedSecretLiteralGuard().run(tmp_path, profile) == []


def test_terraform_hardcoded_secret_literal_applies_gate() -> None:
    profile = mkprofile(Path("/tmp"), features={"python"})
    assert TerraformHardcodedSecretLiteralGuard().applies(profile) is False


def test_terraform_hardcoded_secret_literal_applies_with_terraform() -> None:
    profile = mkprofile(Path("/tmp"), features={"terraform"})
    assert TerraformHardcodedSecretLiteralGuard().applies(profile) is True


def test_terraform_hardcoded_secret_literal_user_data_pragma_inside_the_string_does_not_opt_out(
    tmp_path: Path,
) -> None:
    # #424 E4: a `#` INSIDE the quoted user_data value is script content, not a comment - only a
    # real comment (a script `#` line in the heredoc body above, or one after the closing quote)
    # opts out.
    (tmp_path / "instance.tf").write_text(
        'resource "aws_instance" "app" {\n'
        '  user_data = "export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE # security: allow-tf-hardcoded-secret"\n'
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    findings = TerraformHardcodedSecretLiteralGuard().run(tmp_path, profile)
    assert [f.rule for f in findings] == ["terraform-hardcoded-secret-literal/user-data-embedded-secret"]
