from __future__ import annotations

from agentsec.guards.gcp_kms_key_public import GcpKmsKeyPublicGuard
from tests.guards._common import *  # noqa: F401,F403


def test_gcp_kms_key_public_flags_iam_member_all_users(tmp_path: Path) -> None:
    (tmp_path / "kms.tf").write_text(
        'resource "google_kms_crypto_key_iam_member" "bad" {\n'
        "  crypto_key_id = google_kms_crypto_key.key.id\n"
        '  role          = "roles/cloudkms.cryptoKeyEncrypterDecrypter"\n'
        '  member        = "allUsers"\n'
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    findings = GcpKmsKeyPublicGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "gcp-kms-key-public/public-member"
    assert findings[0].severity == "high"


def test_gcp_kms_key_public_flags_iam_binding_all_authenticated_users(tmp_path: Path) -> None:
    (tmp_path / "kms.tf").write_text(
        'resource "google_kms_crypto_key_iam_binding" "bad" {\n'
        "  crypto_key_id = google_kms_crypto_key.key.id\n"
        '  role          = "roles/cloudkms.cryptoKeyEncrypterDecrypter"\n'
        "  members = [\n"
        '    "allAuthenticatedUsers",\n'
        '    "user:foo@example.com",\n'
        "  ]\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    findings = GcpKmsKeyPublicGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "gcp-kms-key-public/public-member"


def test_gcp_kms_key_public_flags_iam_policy_data(tmp_path: Path) -> None:
    (tmp_path / "kms.tf").write_text(
        'resource "google_kms_crypto_key_iam_policy" "bad" {\n'
        "  crypto_key_id = google_kms_crypto_key.key.id\n"
        "  policy_data = data.google_iam_policy.admin.policy_data\n"
        "  # bindings { members = [\"allUsers\"] } lives in the referenced data source,\n"
        "  # but a literal mention on this line still fires (matches checkov's literal scan)\n"
        '  members_hint = "allUsers"\n'
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    findings = GcpKmsKeyPublicGuard().run(tmp_path, profile)
    assert len(findings) == 1


def test_gcp_kms_key_public_silent_specific_user(tmp_path: Path) -> None:
    (tmp_path / "kms.tf").write_text(
        'resource "google_kms_crypto_key_iam_member" "ok" {\n'
        "  crypto_key_id = google_kms_crypto_key.key.id\n"
        '  role          = "roles/cloudkms.cryptoKeyEncrypterDecrypter"\n'
        '  member        = "user:foo@example.com"\n'
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    assert GcpKmsKeyPublicGuard().run(tmp_path, profile) == []


def test_gcp_kms_key_public_silent_comment_mention(tmp_path: Path) -> None:
    (tmp_path / "kms.tf").write_text(
        'resource "google_kms_crypto_key_iam_member" "ok" {\n'
        "  crypto_key_id = google_kms_crypto_key.key.id\n"
        '  role          = "roles/cloudkms.cryptoKeyEncrypterDecrypter"\n'
        "  # do NOT set member to allUsers here\n"
        '  member        = "user:foo@example.com"\n'
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    assert GcpKmsKeyPublicGuard().run(tmp_path, profile) == []


def test_gcp_kms_key_public_silent_other_resource_type(tmp_path: Path) -> None:
    (tmp_path / "kms.tf").write_text(
        'resource "google_kms_crypto_key" "key" {\n'
        '  name     = "key"\n'
        '  key_ring = google_kms_key_ring.ring.id\n'
        "  # not an IAM resource -- allUsers here would be a config error, not a KMS grant\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    assert GcpKmsKeyPublicGuard().run(tmp_path, profile) == []


def test_gcp_kms_key_public_pragma_silences(tmp_path: Path) -> None:
    (tmp_path / "kms.tf").write_text(
        'resource "google_kms_crypto_key_iam_member" "bad" {\n'
        "  crypto_key_id = google_kms_crypto_key.key.id\n"
        '  role          = "roles/cloudkms.cryptoKeyEncrypterDecrypter"\n'
        '  member        = "allUsers"\n'
        "  # security: allow-gcp-kms-key-public\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    assert GcpKmsKeyPublicGuard().run(tmp_path, profile) == []


def test_gcp_kms_key_public_flags_storage_bucket_iam_member_all_users(tmp_path: Path) -> None:
    # extension to google_storage_bucket_iam_* (KICS
    # cloud_storage_anonymous_or_publicly_accessible) — same guard, same rule id.
    (tmp_path / "storage.tf").write_text(
        'resource "google_storage_bucket_iam_member" "bad" {\n'
        "  bucket = google_storage_bucket.data.name\n"
        '  role   = "roles/storage.objectViewer"\n'
        '  member = "allUsers"\n'
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    findings = GcpKmsKeyPublicGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "gcp-kms-key-public/public-member"
    assert findings[0].severity == "high"
    assert "Cloud Storage bucket" in findings[0].message


def test_gcp_kms_key_public_flags_storage_bucket_iam_binding_all_authenticated_users(
    tmp_path: Path,
) -> None:
    # Bypass-attempt: allAuthenticatedUsers mixed into a `members` list alongside a real
    # principal must still fire (indirect pattern, mirrors the KMS binding test above).
    (tmp_path / "storage.tf").write_text(
        'resource "google_storage_bucket_iam_binding" "bad" {\n'
        "  bucket = google_storage_bucket.data.name\n"
        '  role   = "roles/storage.objectViewer"\n'
        "  members = [\n"
        '    "allAuthenticatedUsers",\n'
        '    "user:foo@example.com",\n'
        "  ]\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    findings = GcpKmsKeyPublicGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "gcp-kms-key-public/public-member"


def test_gcp_kms_key_public_storage_bucket_silent_specific_member(tmp_path: Path) -> None:
    # FP-bait: an ordinary, specific-principal Cloud Storage IAM binding must stay silent.
    (tmp_path / "storage.tf").write_text(
        'resource "google_storage_bucket_iam_member" "ok" {\n'
        "  bucket = google_storage_bucket.data.name\n"
        '  role   = "roles/storage.objectViewer"\n'
        '  member = "serviceAccount:reader@my-project.iam.gserviceaccount.com"\n'
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    assert GcpKmsKeyPublicGuard().run(tmp_path, profile) == []


def test_gcp_kms_key_public_storage_bucket_pragma_silences(tmp_path: Path) -> None:
    (tmp_path / "storage.tf").write_text(
        'resource "google_storage_bucket_iam_member" "bad" {\n'
        "  bucket = google_storage_bucket.data.name\n"
        '  role   = "roles/storage.objectViewer"\n'
        '  member = "allUsers"\n'
        "  # security: allow-gcp-kms-key-public\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    assert GcpKmsKeyPublicGuard().run(tmp_path, profile) == []


def test_gcp_kms_key_public_still_flags_kms_after_storage_extension(tmp_path: Path) -> None:
    # Narrowing-direction control: the original KMS detection must be unaffected by the
    # storage-bucket resource-type-set addition.
    (tmp_path / "kms.tf").write_text(
        'resource "google_kms_crypto_key_iam_member" "bad" {\n'
        "  crypto_key_id = google_kms_crypto_key.key.id\n"
        '  role          = "roles/cloudkms.cryptoKeyEncrypterDecrypter"\n'
        '  member        = "allUsers"\n'
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    findings = GcpKmsKeyPublicGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert "grants KMS access" in findings[0].message


def test_gcp_kms_key_public_applies_gate() -> None:
    profile = mkprofile(Path("/tmp"), features={"python"})
    assert GcpKmsKeyPublicGuard().applies(profile) is False


def test_gcp_kms_key_public_applies_with_terraform() -> None:
    profile = mkprofile(Path("/tmp"), features={"terraform"})
    assert GcpKmsKeyPublicGuard().applies(profile) is True
