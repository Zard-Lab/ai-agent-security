from __future__ import annotations

from agentsec.guards.cloud_metadata_endpoint_literal import CloudMetadataEndpointLiteralGuard
from tests.guards._common import *  # noqa: F401,F403


def test_cloud_metadata_endpoint_flags_aws_imds(tmp_path: Path) -> None:
    (tmp_path / "steal.py").write_text(
        'os.system("curl http://169.254.169.254/latest/meta-data/iam/security-credentials/")\n',
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    findings = CloudMetadataEndpointLiteralGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "cloud-metadata-endpoint-literal/hardcoded-reference"
    assert findings[0].severity == "high"

def test_cloud_metadata_endpoint_flags_gcp_alias(tmp_path: Path) -> None:
    (tmp_path / "steal.sh").write_text(
        'curl -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/\n',
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    findings = CloudMetadataEndpointLiteralGuard().run(tmp_path, profile)
    assert len(findings) == 1

def test_cloud_metadata_endpoint_flags_alibaba(tmp_path: Path) -> None:
    (tmp_path / "steal.py").write_text(
        'requests.get("http://100.100.100.200/latest/meta-data/")\n',
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    findings = CloudMetadataEndpointLiteralGuard().run(tmp_path, profile)
    assert len(findings) == 1

def test_cloud_metadata_endpoint_silent_unrelated_ip(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        'requests.get("http://10.0.0.5/health")\n',
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    assert CloudMetadataEndpointLiteralGuard().run(tmp_path, profile) == []

def test_cloud_metadata_endpoint_silent_comment(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "# Note: this app does NOT query 169.254.169.254\n"
        "x = 1\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    assert CloudMetadataEndpointLiteralGuard().run(tmp_path, profile) == []

def test_cloud_metadata_endpoint_pragma_silences(tmp_path: Path) -> None:
    content = (
        "# security: allow-metadata-endpoint\n"
        'requests.get("http://169.254.169.254/latest/meta-data/")\n'
    )
    (tmp_path / "cloud_init.py").write_text(content, encoding="utf-8")
    profile = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    assert CloudMetadataEndpointLiteralGuard().run(tmp_path, profile) == []

def test_cloud_metadata_endpoint_covers_shell_only_repo(tmp_path: Path) -> None:
    # Regression (PR #393 review #1): universal guard fires the shell literal on a repo with
    # no `python` feature -- a language-feature gate silently missed this.
    (tmp_path / "steal.sh").write_text(
        "curl http://169.254.169.254/latest/meta-data/iam/\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features=set())
    assert CloudMetadataEndpointLiteralGuard().applies(profile) is True
    assert len(CloudMetadataEndpointLiteralGuard().run(tmp_path, profile)) == 1

def test_cloud_metadata_endpoint_skips_nonproduct_path(tmp_path: Path) -> None:
    # Regression (PR #393 review #2): a metadata literal in a security test file is skipped.
    tests_dir = tmp_path / "tests"
    tests_dir.mkdir()
    (tests_dir / "test_ssrf.py").write_text(
        'TARGET = "http://169.254.169.254/latest/meta-data/"\n',
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    assert CloudMetadataEndpointLiteralGuard().run(tmp_path, profile) == []

def test_cloud_metadata_endpoint_applies_universally() -> None:
    # Universal guard: metadata-endpoint literals can appear in any stack.
    assert CloudMetadataEndpointLiteralGuard().applies(mkprofile(Path("/tmp"), features={"java"})) is True
    assert CloudMetadataEndpointLiteralGuard().applies(mkprofile(Path("/tmp"), features=set())) is True
