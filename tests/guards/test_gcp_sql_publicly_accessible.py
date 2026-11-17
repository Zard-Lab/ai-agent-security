from __future__ import annotations

from agentsec.guards.gcp_sql_publicly_accessible import GcpSqlPubliclyAccessibleGuard
from tests.guards._common import *  # noqa: F401,F403


def test_gcp_sql_publicly_accessible_flags_authorized_network_wildcard(tmp_path: Path) -> None:
    (tmp_path / "sql.tf").write_text(
        'resource "google_sql_database_instance" "app" {\n'
        '  name             = "app-db"\n'
        '  database_version = "POSTGRES_15"\n'
        "  settings {\n"
        '    tier = "db-f1-micro"\n'
        "    ip_configuration {\n"
        "      ipv4_enabled = true\n"
        "      authorized_networks {\n"
        '        value = "0.0.0.0/0"\n'
        '        name  = "all"\n'
        "      }\n"
        "    }\n"
        "  }\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    findings = GcpSqlPubliclyAccessibleGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "gcp-sql-publicly-accessible/authorized-network-wildcard"
    assert findings[0].severity == "high"


def test_gcp_sql_publicly_accessible_flags_authorized_network_wildcard_among_many(
    tmp_path: Path,
) -> None:
    # Bypass-attempt: an 0.0.0.0/0 entry mixed in among several legitimate-looking narrow
    # entries (a repeated `authorized_networks` block) must still fire.
    (tmp_path / "sql.tf").write_text(
        'resource "google_sql_database_instance" "app" {\n'
        "  settings {\n"
        "    ip_configuration {\n"
        "      authorized_networks {\n"
        '        value = "203.0.113.4/32"\n'
        '        name  = "office"\n'
        "      }\n"
        "      authorized_networks {\n"
        '        value = "0.0.0.0/0"\n'
        '        name  = "temporary-debug-DO-NOT-SHIP"\n'
        "      }\n"
        "    }\n"
        "  }\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    findings = GcpSqlPubliclyAccessibleGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "gcp-sql-publicly-accessible/authorized-network-wildcard"


def test_gcp_sql_publicly_accessible_flags_public_ip_no_restriction(tmp_path: Path) -> None:
    (tmp_path / "sql.tf").write_text(
        'resource "google_sql_database_instance" "app" {\n'
        "  settings {\n"
        "    ip_configuration {\n"
        "      ipv4_enabled = true\n"
        "    }\n"
        "  }\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    findings = GcpSqlPubliclyAccessibleGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "gcp-sql-publicly-accessible/public-ip-no-restriction"


def test_gcp_sql_publicly_accessible_flags_missing_ip_configuration(tmp_path: Path) -> None:
    (tmp_path / "sql.tf").write_text(
        'resource "google_sql_database_instance" "app" {\n'
        '  name             = "app-db"\n'
        '  database_version = "POSTGRES_15"\n'
        "  settings {\n"
        '    tier = "db-f1-micro"\n'
        "  }\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    findings = GcpSqlPubliclyAccessibleGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "gcp-sql-publicly-accessible/missing-ip-configuration"


def test_gcp_sql_publicly_accessible_flags_missing_settings_block(tmp_path: Path) -> None:
    # The `settings` block itself missing entirely is the same "no restriction configured"
    # shape as `ip_configuration` alone being missing.
    (tmp_path / "sql.tf").write_text(
        'resource "google_sql_database_instance" "app" {\n'
        '  name             = "app-db"\n'
        '  database_version = "POSTGRES_15"\n'
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    findings = GcpSqlPubliclyAccessibleGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "gcp-sql-publicly-accessible/missing-ip-configuration"


def test_gcp_sql_publicly_accessible_silent_with_private_network(tmp_path: Path) -> None:
    # FP-bait: a public IP with a private_network (VPC peering) set is a legitimate,
    # deliberately-configured pattern and must stay silent.
    (tmp_path / "sql.tf").write_text(
        'resource "google_sql_database_instance" "app" {\n'
        "  settings {\n"
        "    ip_configuration {\n"
        "      ipv4_enabled    = true\n"
        "      private_network = google_compute_network.vpc.id\n"
        "    }\n"
        "  }\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    assert GcpSqlPubliclyAccessibleGuard().run(tmp_path, profile) == []


def test_gcp_sql_publicly_accessible_silent_with_narrow_authorized_network(
    tmp_path: Path,
) -> None:
    # FP-bait: a narrow, specific IP allowlist is exactly the safe pattern this guard should
    # not flag.
    (tmp_path / "sql.tf").write_text(
        'resource "google_sql_database_instance" "app" {\n'
        "  settings {\n"
        "    ip_configuration {\n"
        "      ipv4_enabled = true\n"
        "      authorized_networks {\n"
        '        value = "203.0.113.4/32"\n'
        '        name  = "office"\n'
        "      }\n"
        "    }\n"
        "  }\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    assert GcpSqlPubliclyAccessibleGuard().run(tmp_path, profile) == []


def test_gcp_sql_publicly_accessible_silent_ipv4_disabled(tmp_path: Path) -> None:
    (tmp_path / "sql.tf").write_text(
        'resource "google_sql_database_instance" "app" {\n'
        "  settings {\n"
        "    ip_configuration {\n"
        "      ipv4_enabled    = false\n"
        "      private_network = google_compute_network.vpc.id\n"
        "    }\n"
        "  }\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    assert GcpSqlPubliclyAccessibleGuard().run(tmp_path, profile) == []


def test_gcp_sql_publicly_accessible_silent_other_resource(tmp_path: Path) -> None:
    (tmp_path / "other.tf").write_text(
        'resource "google_compute_instance" "app" {\n'
        "  # no ip_configuration here either; unrelated resource type\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    assert GcpSqlPubliclyAccessibleGuard().run(tmp_path, profile) == []


def test_gcp_sql_publicly_accessible_silent_comment_mention(tmp_path: Path) -> None:
    (tmp_path / "sql.tf").write_text(
        'resource "google_sql_database_instance" "app" {\n'
        "  settings {\n"
        "    ip_configuration {\n"
        '      # authorized_networks { value = "0.0.0.0/0" }\n'
        "      ipv4_enabled    = true\n"
        "      private_network = google_compute_network.vpc.id\n"
        "    }\n"
        "  }\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    assert GcpSqlPubliclyAccessibleGuard().run(tmp_path, profile) == []


def test_gcp_sql_publicly_accessible_pragma_silences(tmp_path: Path) -> None:
    (tmp_path / "sql.tf").write_text(
        'resource "google_sql_database_instance" "app" {\n'
        "  # security: allow-gcp-sql-public\n"
        "  settings {\n"
        "    ip_configuration {\n"
        "      ipv4_enabled = true\n"
        "    }\n"
        "  }\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    assert GcpSqlPubliclyAccessibleGuard().run(tmp_path, profile) == []


def test_gcp_sql_publicly_accessible_applies_gate() -> None:
    profile = mkprofile(Path("/tmp"), features={"python"})
    assert GcpSqlPubliclyAccessibleGuard().applies(profile) is False


def test_gcp_sql_publicly_accessible_applies_with_terraform() -> None:
    profile = mkprofile(Path("/tmp"), features={"terraform"})
    assert GcpSqlPubliclyAccessibleGuard().applies(profile) is True
