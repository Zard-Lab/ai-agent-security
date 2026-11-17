from __future__ import annotations

from agentsec.guards.gcp_kms_rotation_period_not_set import GcpKmsRotationPeriodNotSetGuard
from tests.guards._common import *  # noqa: F401,F403


def test_gcp_kms_rotation_period_flags_missing_attribute(tmp_path: Path) -> None:
    (tmp_path / "kms.tf").write_text(
        'resource "google_kms_crypto_key" "app" {\n'
        '  name     = "app-key"\n'
        '  key_ring = google_kms_key_ring.ring.id\n'
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    findings = GcpKmsRotationPeriodNotSetGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "gcp-kms-rotation-period-not-set/missing-rotation-period"
    assert findings[0].severity == "medium"
    assert findings[0].standards == ["OWASP:A02", "CWE-320"]


def test_gcp_kms_rotation_period_silent_when_present(tmp_path: Path) -> None:
    (tmp_path / "kms.tf").write_text(
        'resource "google_kms_crypto_key" "app" {\n'
        '  name            = "app-key"\n'
        '  key_ring        = google_kms_key_ring.ring.id\n'
        '  rotation_period = "7776000s"\n'
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    assert GcpKmsRotationPeriodNotSetGuard().run(tmp_path, profile) == []


def test_gcp_kms_rotation_period_skips_asymmetric_key(tmp_path: Path) -> None:
    (tmp_path / "kms.tf").write_text(
        'resource "google_kms_crypto_key" "app" {\n'
        '  name     = "app-key"\n'
        '  key_ring = google_kms_key_ring.ring.id\n'
        '  purpose  = "ASYMMETRIC_SIGN"\n'
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    assert GcpKmsRotationPeriodNotSetGuard().run(tmp_path, profile) == []


def test_gcp_kms_rotation_period_skips_asymmetric_decrypt_key(tmp_path: Path) -> None:
    (tmp_path / "kms.tf").write_text(
        'resource "google_kms_crypto_key" "app" {\n'
        '  name     = "app-key"\n'
        '  key_ring = google_kms_key_ring.ring.id\n'
        '  purpose  = "ASYMMETRIC_DECRYPT"\n'
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    assert GcpKmsRotationPeriodNotSetGuard().run(tmp_path, profile) == []


def test_gcp_kms_rotation_period_silent_other_resource(tmp_path: Path) -> None:
    (tmp_path / "ring.tf").write_text(
        'resource "google_kms_key_ring" "ring" {\n'
        '  name     = "ring"\n'
        '  location = "global"\n'
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    assert GcpKmsRotationPeriodNotSetGuard().run(tmp_path, profile) == []


def test_gcp_kms_rotation_period_pragma_silences(tmp_path: Path) -> None:
    (tmp_path / "kms.tf").write_text(
        'resource "google_kms_crypto_key" "app" {\n'
        '  name = "app-key"\n'
        "  # security: allow-gcp-kms-rotation-period\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    assert GcpKmsRotationPeriodNotSetGuard().run(tmp_path, profile) == []


def test_gcp_kms_rotation_period_applies_gate() -> None:
    profile = mkprofile(Path("/tmp"), features={"python"})
    assert GcpKmsRotationPeriodNotSetGuard().applies(profile) is False


def test_gcp_kms_rotation_period_applies_with_terraform() -> None:
    profile = mkprofile(Path("/tmp"), features={"terraform"})
    assert GcpKmsRotationPeriodNotSetGuard().applies(profile) is True


def test_gcp_kms_rotation_period_commented_purpose_does_not_suppress(tmp_path: Path) -> None:
    # A commented-out `# purpose = "ASYMMETRIC_SIGN"` must NOT be read as the real purpose on a
    # genuinely symmetric (rotatable) key missing rotation_period -> false negative if honored.
    (tmp_path / "kms.tf").write_text(
        'resource "google_kms_crypto_key" "app" {\n'
        '  name = "app-key"\n'
        '  # purpose = "ASYMMETRIC_SIGN"\n'
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    findings = GcpKmsRotationPeriodNotSetGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "gcp-kms-rotation-period-not-set/missing-rotation-period"


def test_gcp_kms_rotation_period_commented_rotation_does_not_suppress(tmp_path: Path) -> None:
    # A commented-out `# rotation_period = "..."` must NOT be read as the real attribute on a
    # genuinely unrotated key -> false negative if honored.
    (tmp_path / "kms.tf").write_text(
        'resource "google_kms_crypto_key" "app" {\n'
        '  name = "app-key"\n'
        '  # rotation_period = "7776000s"\n'
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    findings = GcpKmsRotationPeriodNotSetGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "gcp-kms-rotation-period-not-set/missing-rotation-period"
