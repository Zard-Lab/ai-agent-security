from __future__ import annotations

from agentsec.guards.azure_keyvault_key_no_expiration import AzureKeyvaultKeyNoExpirationGuard
from tests.guards._common import *  # noqa: F401,F403


def test_azure_keyvault_key_no_expiration_flags_missing_attribute(tmp_path: Path) -> None:
    (tmp_path / "kv.tf").write_text(
        'resource "azurerm_key_vault_key" "app" {\n'
        '  name         = "app-key"\n'
        "  key_vault_id = azurerm_key_vault.main.id\n"
        '  key_type     = "RSA"\n'
        "  key_size     = 2048\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    findings = AzureKeyvaultKeyNoExpirationGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "azure-keyvault-key-no-expiration/missing-expiration-date"
    assert findings[0].severity == "medium"
    assert findings[0].standards == ["OWASP:A02", "CWE-320"]


def test_azure_keyvault_key_no_expiration_silent_when_set(tmp_path: Path) -> None:
    (tmp_path / "kv.tf").write_text(
        'resource "azurerm_key_vault_key" "app" {\n'
        '  name             = "app-key"\n'
        "  key_vault_id     = azurerm_key_vault.main.id\n"
        '  key_type         = "RSA"\n'
        "  key_size         = 2048\n"
        '  expiration_date  = "2027-12-31T23:59:59Z"\n'
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    assert AzureKeyvaultKeyNoExpirationGuard().run(tmp_path, profile) == []


def test_azure_keyvault_key_no_expiration_silent_other_resource(tmp_path: Path) -> None:
    # The vault itself (azurerm_key_vault) is a different resource type from the key stored
    # inside it (azurerm_key_vault_key) and must never be scanned by this guard, even if it
    # also happens to lack an expiration_date-shaped attribute.
    (tmp_path / "vault.tf").write_text(
        'resource "azurerm_key_vault" "main" {\n'
        '  name = "main-vault"\n'
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    assert AzureKeyvaultKeyNoExpirationGuard().run(tmp_path, profile) == []


def test_azure_keyvault_key_no_expiration_pragma_silences(tmp_path: Path) -> None:
    (tmp_path / "kv.tf").write_text(
        'resource "azurerm_key_vault_key" "app" {\n'
        '  name = "app-key"\n'
        "  # security: allow-azure-keyvault-key-expiration\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    assert AzureKeyvaultKeyNoExpirationGuard().run(tmp_path, profile) == []


def test_azure_keyvault_key_no_expiration_applies_gate() -> None:
    profile = mkprofile(Path("/tmp"), features={"python"})
    assert AzureKeyvaultKeyNoExpirationGuard().applies(profile) is False


def test_azure_keyvault_key_no_expiration_applies_with_terraform() -> None:
    profile = mkprofile(Path("/tmp"), features={"terraform"})
    assert AzureKeyvaultKeyNoExpirationGuard().applies(profile) is True


def test_azure_keyvault_key_no_expiration_comment_does_not_suppress_finding(
    tmp_path: Path,
) -> None:
    # A commented `# expiration_date = "..."` must NOT be read as the real attribute on a key
    # that genuinely never expires (comment-blind blob search -> false negative).
    (tmp_path / "kv.tf").write_text(
        'resource "azurerm_key_vault_key" "app" {\n'
        '  name = "app-key"\n'
        '  # TODO: expiration_date = "2027-12-31T23:59:59Z"\n'
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    findings = AzureKeyvaultKeyNoExpirationGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "azure-keyvault-key-no-expiration/missing-expiration-date"


def test_azure_keyvault_key_no_expiration_brace_in_string_does_not_truncate_block(
    tmp_path: Path,
) -> None:
    # An unbalanced `}` inside a tag string used to close the resource block early, dropping
    # the `expiration_date` line below it -> false positive on a key that does expire.
    (tmp_path / "kv.tf").write_text(
        'resource "azurerm_key_vault_key" "app" {\n'
        '  tags            = { Name = "prod}key" }\n'
        '  expiration_date = "2027-12-31T23:59:59Z"\n'
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    assert AzureKeyvaultKeyNoExpirationGuard().run(tmp_path, profile) == []
