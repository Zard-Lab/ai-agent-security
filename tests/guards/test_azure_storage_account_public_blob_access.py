from __future__ import annotations

from agentsec.guards.azure_storage_account_public_blob_access import (
    AzureStorageAccountPublicBlobAccessGuard,
)
from tests.guards._common import *  # noqa: F401,F403


def test_azure_storage_public_blob_flags_missing_attribute(tmp_path: Path) -> None:
    (tmp_path / "storage.tf").write_text(
        'resource "azurerm_storage_account" "app" {\n'
        '  name                     = "appstorage"\n'
        '  account_tier             = "Standard"\n'
        '  account_replication_type = "LRS"\n'
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    findings = AzureStorageAccountPublicBlobAccessGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "azure-storage-account-public-blob-access/missing-or-enabled"
    assert findings[0].severity == "high"


def test_azure_storage_public_blob_flags_explicit_true(tmp_path: Path) -> None:
    (tmp_path / "storage.tf").write_text(
        'resource "azurerm_storage_account" "app" {\n'
        '  name                       = "appstorage"\n'
        "  allow_blob_public_access  = true\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    findings = AzureStorageAccountPublicBlobAccessGuard().run(tmp_path, profile)
    assert len(findings) == 1


def test_azure_storage_public_blob_silent_when_explicitly_false(tmp_path: Path) -> None:
    (tmp_path / "storage.tf").write_text(
        'resource "azurerm_storage_account" "app" {\n'
        "  allow_blob_public_access = false\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    assert AzureStorageAccountPublicBlobAccessGuard().run(tmp_path, profile) == []


def test_azure_storage_public_blob_silent_other_resource(tmp_path: Path) -> None:
    # Bypass-attempt / resource-type scoping control: an unrelated resource carrying the same
    # attribute name must not trip this guard.
    (tmp_path / "kv.tf").write_text(
        'resource "azurerm_key_vault" "app" {\n'
        '  name = "app-kv"\n'
        "  allow_blob_public_access = true\n"  # not a real KV attribute; scoping control only
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    assert AzureStorageAccountPublicBlobAccessGuard().run(tmp_path, profile) == []


def test_azure_storage_public_blob_silent_comment_mention(tmp_path: Path) -> None:
    # FP-bait: a commented-out `allow_blob_public_access = false` must not suppress a real
    # missing-attribute finding on the same resource.
    (tmp_path / "storage.tf").write_text(
        'resource "azurerm_storage_account" "app" {\n'
        "  # allow_blob_public_access = false\n"
        '  name = "appstorage"\n'
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    findings = AzureStorageAccountPublicBlobAccessGuard().run(tmp_path, profile)
    assert len(findings) == 1


def test_azure_storage_public_blob_pragma_silences(tmp_path: Path) -> None:
    (tmp_path / "storage.tf").write_text(
        'resource "azurerm_storage_account" "app" {\n'
        "  allow_blob_public_access = true\n"
        "  # security: allow-azure-storage-public-blob-access\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    assert AzureStorageAccountPublicBlobAccessGuard().run(tmp_path, profile) == []


def test_azure_storage_public_blob_applies_gate() -> None:
    profile = mkprofile(Path("/tmp"), features={"python"})
    assert AzureStorageAccountPublicBlobAccessGuard().applies(profile) is False


def test_azure_storage_public_blob_applies_with_terraform() -> None:
    profile = mkprofile(Path("/tmp"), features={"terraform"})
    assert AzureStorageAccountPublicBlobAccessGuard().applies(profile) is True
