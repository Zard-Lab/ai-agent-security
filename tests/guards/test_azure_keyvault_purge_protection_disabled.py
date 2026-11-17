from __future__ import annotations

from agentsec.guards.azure_keyvault_purge_protection_disabled import (
    AzureKeyvaultPurgeProtectionDisabledGuard,
)
from tests.guards._common import *  # noqa: F401,F403


def test_azure_keyvault_purge_protection_flags_missing_attribute(tmp_path: Path) -> None:
    (tmp_path / "kv.tf").write_text(
        'resource "azurerm_key_vault" "app" {\n'
        '  name     = "app-kv"\n'
        '  sku_name = "standard"\n'
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    findings = AzureKeyvaultPurgeProtectionDisabledGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == (
        "azure-keyvault-purge-protection-disabled/missing-purge-protection"
    )
    assert findings[0].severity == "medium"


def test_azure_keyvault_purge_protection_flags_explicit_false(tmp_path: Path) -> None:
    (tmp_path / "kv.tf").write_text(
        'resource "azurerm_key_vault" "app" {\n'
        "  purge_protection_enabled = false\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    findings = AzureKeyvaultPurgeProtectionDisabledGuard().run(tmp_path, profile)
    assert len(findings) == 1


def test_azure_keyvault_purge_protection_silent_when_true(tmp_path: Path) -> None:
    (tmp_path / "kv.tf").write_text(
        'resource "azurerm_key_vault" "app" {\n'
        "  purge_protection_enabled = true\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    assert AzureKeyvaultPurgeProtectionDisabledGuard().run(tmp_path, profile) == []


def test_azure_keyvault_purge_protection_silent_other_resource(tmp_path: Path) -> None:
    (tmp_path / "vault.tf").write_text(
        'resource "azurerm_key_vault_secret" "app" {\n'
        '  name = "app-secret"\n'
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    assert AzureKeyvaultPurgeProtectionDisabledGuard().run(tmp_path, profile) == []


def test_azure_keyvault_purge_protection_pragma_silences(tmp_path: Path) -> None:
    (tmp_path / "kv.tf").write_text(
        'resource "azurerm_key_vault" "app" {\n'
        "  # security: allow-azure-keyvault-purge-protection\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    assert AzureKeyvaultPurgeProtectionDisabledGuard().run(tmp_path, profile) == []


def test_azure_keyvault_purge_protection_applies_gate() -> None:
    profile = mkprofile(Path("/tmp"), features={"python"})
    assert AzureKeyvaultPurgeProtectionDisabledGuard().applies(profile) is False


def test_azure_keyvault_purge_protection_applies_with_terraform() -> None:
    profile = mkprofile(Path("/tmp"), features={"terraform"})
    assert AzureKeyvaultPurgeProtectionDisabledGuard().applies(profile) is True


def test_azure_keyvault_purge_protection_brace_in_string_does_not_truncate_block(
    tmp_path: Path,
) -> None:
    # An unbalanced `}` inside a tag string used to close the resource block early, dropping
    # the `purge_protection_enabled = true` line below it -> false positive on a protected vault.
    (tmp_path / "kv.tf").write_text(
        'resource "azurerm_key_vault" "app" {\n'
        '  tags                      = { Name = "prod}kv" }\n'
        "  purge_protection_enabled  = true\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    assert AzureKeyvaultPurgeProtectionDisabledGuard().run(tmp_path, profile) == []


def test_azure_keyvault_purge_protection_comment_does_not_suppress_finding(
    tmp_path: Path,
) -> None:
    # A commented `# purge_protection_enabled = true` must NOT be read as the real attribute on
    # a genuinely unprotected vault (comment-blind blob search -> false negative).
    (tmp_path / "kv.tf").write_text(
        'resource "azurerm_key_vault" "app" {\n'
        '  name = "app-kv"\n'
        "  # TODO: purge_protection_enabled = true\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    findings = AzureKeyvaultPurgeProtectionDisabledGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == (
        "azure-keyvault-purge-protection-disabled/missing-purge-protection"
    )
