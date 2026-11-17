from __future__ import annotations

from agentsec.guards.azure_storage_account_https_only import AzureStorageAccountHttpsOnlyGuard
from tests.guards._common import *  # noqa: F401,F403


def test_azure_storage_https_only_flags_missing_attribute(tmp_path: Path) -> None:
    (tmp_path / "storage.tf").write_text(
        'resource "azurerm_storage_account" "app" {\n'
        '  name                     = "appstorage"\n'
        '  account_tier             = "Standard"\n'
        '  account_replication_type = "LRS"\n'
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    findings = AzureStorageAccountHttpsOnlyGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "azure-storage-account-https-only/missing-or-disabled"
    assert findings[0].severity == "medium"


def test_azure_storage_https_only_flags_legacy_attribute_false(tmp_path: Path) -> None:
    (tmp_path / "storage.tf").write_text(
        'resource "azurerm_storage_account" "app" {\n'
        "  enable_https_traffic_only = false\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    findings = AzureStorageAccountHttpsOnlyGuard().run(tmp_path, profile)
    assert len(findings) == 1


def test_azure_storage_https_only_flags_v4_attribute_false(tmp_path: Path) -> None:
    # The v4 provider rename — the exact bypass this guard exists to close (a guard hard-coded
    # to only the legacy name would silently miss this after a provider upgrade).
    (tmp_path / "storage.tf").write_text(
        'resource "azurerm_storage_account" "app" {\n'
        "  https_traffic_only_enabled = false\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    findings = AzureStorageAccountHttpsOnlyGuard().run(tmp_path, profile)
    assert len(findings) == 1


def test_azure_storage_https_only_silent_with_legacy_attribute_true(tmp_path: Path) -> None:
    (tmp_path / "storage.tf").write_text(
        'resource "azurerm_storage_account" "app" {\n'
        "  enable_https_traffic_only = true\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    assert AzureStorageAccountHttpsOnlyGuard().run(tmp_path, profile) == []


def test_azure_storage_https_only_silent_with_v4_attribute_true(tmp_path: Path) -> None:
    (tmp_path / "storage.tf").write_text(
        'resource "azurerm_storage_account" "app" {\n'
        "  https_traffic_only_enabled = true\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    assert AzureStorageAccountHttpsOnlyGuard().run(tmp_path, profile) == []


def test_azure_storage_https_only_silent_other_resource(tmp_path: Path) -> None:
    (tmp_path / "kv.tf").write_text(
        'resource "azurerm_key_vault" "app" {\n'
        '  name = "app-kv"\n'
        "  https_traffic_only_enabled = false\n"  # not a real KV attribute, scoping control only
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    assert AzureStorageAccountHttpsOnlyGuard().run(tmp_path, profile) == []


def test_azure_storage_https_only_silent_comment_mention(tmp_path: Path) -> None:
    (tmp_path / "storage.tf").write_text(
        'resource "azurerm_storage_account" "app" {\n'
        "  # https_traffic_only_enabled = true\n"
        '  name = "appstorage"\n'
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    findings = AzureStorageAccountHttpsOnlyGuard().run(tmp_path, profile)
    assert len(findings) == 1


def test_azure_storage_https_only_pragma_silences(tmp_path: Path) -> None:
    (tmp_path / "storage.tf").write_text(
        'resource "azurerm_storage_account" "app" {\n'
        "  enable_https_traffic_only = false\n"
        "  # security: allow-azure-storage-https-only\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    assert AzureStorageAccountHttpsOnlyGuard().run(tmp_path, profile) == []


def test_azure_storage_https_only_applies_gate() -> None:
    profile = mkprofile(Path("/tmp"), features={"python"})
    assert AzureStorageAccountHttpsOnlyGuard().applies(profile) is False


def test_azure_storage_https_only_applies_with_terraform() -> None:
    profile = mkprofile(Path("/tmp"), features={"terraform"})
    assert AzureStorageAccountHttpsOnlyGuard().applies(profile) is True
