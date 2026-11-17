from __future__ import annotations

from agentsec.guards.azure_mssql_publicly_accessible import AzureMssqlPubliclyAccessibleGuard
from tests.guards._common import *  # noqa: F401,F403


def test_azure_mssql_publicly_accessible_flags_missing_attribute(tmp_path: Path) -> None:
    (tmp_path / "mssql.tf").write_text(
        'resource "azurerm_mssql_server" "app" {\n'
        '  name                         = "app-sql-server"\n'
        '  administrator_login          = "sqladmin"\n'
        '  administrator_login_password = "hunter2!strongpw"\n'
        '  version                      = "12.0"\n'
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    findings = AzureMssqlPubliclyAccessibleGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "azure-mssql-publicly-accessible/missing-or-enabled"
    assert findings[0].severity == "high"


def test_azure_mssql_publicly_accessible_flags_explicit_true(tmp_path: Path) -> None:
    (tmp_path / "mssql.tf").write_text(
        'resource "azurerm_mssql_server" "app" {\n'
        '  name                            = "app-sql-server"\n'
        "  public_network_access_enabled  = true\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    findings = AzureMssqlPubliclyAccessibleGuard().run(tmp_path, profile)
    assert len(findings) == 1


def test_azure_mssql_publicly_accessible_silent_when_explicitly_false(tmp_path: Path) -> None:
    (tmp_path / "mssql.tf").write_text(
        'resource "azurerm_mssql_server" "app" {\n'
        "  public_network_access_enabled = false\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    assert AzureMssqlPubliclyAccessibleGuard().run(tmp_path, profile) == []


def test_azure_mssql_publicly_accessible_silent_other_resource(tmp_path: Path) -> None:
    # Bypass-attempt / resource-type scoping control.
    (tmp_path / "storage.tf").write_text(
        'resource "azurerm_storage_account" "app" {\n'
        '  name = "appstorage"\n'
        "  public_network_access_enabled = true\n"  # not a real storage attribute, scoping control
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    assert AzureMssqlPubliclyAccessibleGuard().run(tmp_path, profile) == []


def test_azure_mssql_publicly_accessible_silent_comment_mention(tmp_path: Path) -> None:
    # FP-bait: a commented-out `false` must not suppress a real missing-attribute finding.
    (tmp_path / "mssql.tf").write_text(
        'resource "azurerm_mssql_server" "app" {\n'
        "  # public_network_access_enabled = false\n"
        '  name = "app-sql-server"\n'
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    findings = AzureMssqlPubliclyAccessibleGuard().run(tmp_path, profile)
    assert len(findings) == 1


def test_azure_mssql_publicly_accessible_pragma_silences(tmp_path: Path) -> None:
    (tmp_path / "mssql.tf").write_text(
        'resource "azurerm_mssql_server" "app" {\n'
        "  public_network_access_enabled = true\n"
        "  # security: allow-azure-mssql-public\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    assert AzureMssqlPubliclyAccessibleGuard().run(tmp_path, profile) == []


def test_azure_mssql_publicly_accessible_applies_gate() -> None:
    profile = mkprofile(Path("/tmp"), features={"python"})
    assert AzureMssqlPubliclyAccessibleGuard().applies(profile) is False


def test_azure_mssql_publicly_accessible_applies_with_terraform() -> None:
    profile = mkprofile(Path("/tmp"), features={"terraform"})
    assert AzureMssqlPubliclyAccessibleGuard().applies(profile) is True
