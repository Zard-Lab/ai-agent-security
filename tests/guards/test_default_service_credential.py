"""Tests for the default-service-credential guard (JadePuffer defense plan B3).

Covers:
  - default-service-credential/minio-default-credential (HIGH)
  - default-service-credential/nacos-default-jwt-secret (HIGH)
  - default-service-credential/grafana-default-credential (HIGH)
  - default-service-credential/grafana-implicit-default-credential (MEDIUM)
  - default-service-credential/postgres-default-credential-exposed (CRITICAL)
"""
from __future__ import annotations

from agentsec.guards.default_service_credential import DefaultServiceCredentialGuard
from tests.guards._common import *  # noqa: F401,F403

_NACOS_SECRET = "SecretKey012345678901234567890123456789012345678901234567890123456789"


def _prof(tmp_path: Path):
    return mkprofile(tmp_path, features={"docker"})


def _run(tmp_path: Path):
    return DefaultServiceCredentialGuard().run(tmp_path, _prof(tmp_path))


def _compose(tmp_path: Path, body: str, name: str = "docker-compose.yml") -> None:
    (tmp_path / name).write_text(body, encoding="utf-8")


def _env(tmp_path: Path, body: str, name: str = ".env") -> None:
    (tmp_path / name).write_text(body, encoding="utf-8")


def _rules(findings: list) -> set[str]:
    return {f.rule for f in findings}


# ── MinIO ─────────────────────────────────────────────────────────────────────

def test_minio_default_pair_fires_in_compose(tmp_path: Path) -> None:
    _compose(
        tmp_path,
        "services:\n  minio:\n    image: minio/minio\n    environment:\n"
        "      MINIO_ROOT_USER: minioadmin\n      MINIO_ROOT_PASSWORD: minioadmin\n",
    )
    findings = _run(tmp_path)
    assert "default-service-credential/minio-default-credential" in _rules(findings)
    hit = next(f for f in findings if f.rule == "default-service-credential/minio-default-credential")
    assert hit.severity == "high"
    assert hit.check_id == "default-service-credential"
    assert hit.standards == ["OWASP:A07", "CWE-1392"]


def test_minio_default_pair_fires_in_env_file(tmp_path: Path) -> None:
    _env(tmp_path, "MINIO_ROOT_USER=minioadmin\nMINIO_ROOT_PASSWORD=minioadmin\n")
    findings = _run(tmp_path)
    assert "default-service-credential/minio-default-credential" in _rules(findings)


def test_minio_deprecated_alias_vars_fire(tmp_path: Path) -> None:
    _compose(
        tmp_path,
        "services:\n  minio:\n    image: minio/minio\n    environment:\n"
        "      MINIO_ACCESS_KEY: minioadmin\n      MINIO_SECRET_KEY: minioadmin\n",
    )
    assert "default-service-credential/minio-default-credential" in _rules(_run(tmp_path))


def test_minio_real_password_stays_silent(tmp_path: Path) -> None:
    # FP-bait: a genuinely changed password must never fire.
    _compose(
        tmp_path,
        "services:\n  minio:\n    image: minio/minio\n    environment:\n"
        "      MINIO_ROOT_USER: minioadmin\n      MINIO_ROOT_PASSWORD: my-real-password\n",
    )
    assert _rules(_run(tmp_path)) == set()


def test_minio_env_var_reference_stays_silent(tmp_path: Path) -> None:
    # FP-bait: an indirection to an external secret is NOT itself a finding.
    _compose(
        tmp_path,
        "services:\n  minio:\n    image: minio/minio\n    environment:\n"
        "      MINIO_ROOT_USER: minioadmin\n      MINIO_ROOT_PASSWORD: ${MINIO_PASS}\n",
    )
    assert _rules(_run(tmp_path)) == set()


# ── Nacos ─────────────────────────────────────────────────────────────────────

def test_nacos_default_jwt_secret_fires(tmp_path: Path) -> None:
    _compose(
        tmp_path,
        "services:\n  nacos:\n    image: nacos/nacos-server\n    environment:\n"
        f"      NACOS_AUTH_TOKEN: {_NACOS_SECRET}\n      NACOS_AUTH_ENABLE: 'true'\n",
    )
    findings = _run(tmp_path)
    hit_rules = _rules(findings)
    assert "default-service-credential/nacos-default-jwt-secret" in hit_rules
    hit = next(f for f in findings if f.rule == "default-service-credential/nacos-default-jwt-secret")
    assert hit.severity == "high"
    assert hit.standards == ["OWASP:A02", "CWE-321"]


def test_nacos_property_style_key_fires(tmp_path: Path) -> None:
    # The legacy application.properties spelling of the same setting, as it would appear if
    # mounted/echoed into a compose environment override (not a `-D` JVM arg, which abuts the
    # property name with no delimiter and is a documented, disclosed miss — see the design doc).
    _compose(
        tmp_path,
        "services:\n  nacos:\n    image: nacos/nacos-server\n    environment:\n"
        f"      NACOS_EXTRA_CONF: nacos.core.auth.plugin.nacos.token.secret.key={_NACOS_SECRET}\n",
    )
    assert "default-service-credential/nacos-default-jwt-secret" in _rules(_run(tmp_path))


def test_nacos_custom_secret_stays_silent(tmp_path: Path) -> None:
    # FP-bait: a real, rotated secret (even one that merely LOOKS similar) must not fire.
    _compose(
        tmp_path,
        "services:\n  nacos:\n    image: nacos/nacos-server\n    environment:\n"
        "      NACOS_AUTH_TOKEN: c29tZS1yZWFsLXJvdGF0ZWQtc2VjcmV0LXZhbHVlLTEyMzQ1Njc4OTA=\n",
    )
    assert _rules(_run(tmp_path)) == set()


def test_nacos_secret_via_env_reference_stays_silent(tmp_path: Path) -> None:
    _env(tmp_path, "NACOS_AUTH_TOKEN=${NACOS_TOKEN}\n")
    assert _rules(_run(tmp_path)) == set()


def test_nacos_jvm_dash_d_system_property_form_fires(tmp_path: Path) -> None:
    # KNOWN GAP fix: a JVM -D system property abuts the property name with no
    # delimiter (`-Dnacos.core...`), so the ordinary `\b` left boundary never matched. A
    # literal, case-sensitive `-D` prefix is now recognized as an additional left boundary
    # for this specific syntax form only.
    _compose(
        tmp_path,
        "services:\n  nacos:\n    image: nacos/nacos-server\n    command:\n"
        f"      - java -Dnacos.core.auth.plugin.nacos.token.secret.key={_NACOS_SECRET} -jar app.jar\n",
    )
    assert "default-service-credential/nacos-default-jwt-secret" in _rules(_run(tmp_path))


def test_nacos_dash_lowercase_d_system_property_form_stays_silent(tmp_path: Path) -> None:
    # FP-bait: the loosened boundary is scoped case-SENSITIVE to the real JVM flag spelling
    # (`-D`, capital D) — a coincidental lowercase `-d` immediately before the name must not
    # match.
    _compose(
        tmp_path,
        "services:\n  app:\n    image: myorg/myapp\n    environment:\n"
        f"      X: -dnacos.core.auth.plugin.nacos.token.secret.key={_NACOS_SECRET}\n",
    )
    assert _rules(_run(tmp_path)) == set()


def test_property_name_abutting_arbitrary_word_stays_silent(tmp_path: Path) -> None:
    # FP-bait: only a literal `-D` immediately before the property name is treated as an
    # additional left boundary — an unrelated identifier that merely happens to end in "D"
    # right before the property name (no dash) must still not match.
    _compose(
        tmp_path,
        "services:\n  app:\n    image: myorg/myapp\n    environment:\n"
        f"      FIELDnacos.core.auth.plugin.nacos.token.secret.key: {_NACOS_SECRET}\n",
    )
    assert _rules(_run(tmp_path)) == set()


# ── Postgres (exposure-gated) ───────────────────────────────────────────────────

def test_postgres_default_credential_exposed_fires_critical(tmp_path: Path) -> None:
    _compose(
        tmp_path,
        "services:\n  db:\n    image: postgres:16\n    ports:\n      - '5432:5432'\n"
        "    environment:\n      POSTGRES_USER: postgres\n      POSTGRES_PASSWORD: postgres\n",
    )
    findings = _run(tmp_path)
    hit = next(
        f for f in findings if f.rule == "default-service-credential/postgres-default-credential-exposed"
    )
    assert hit.severity == "critical"
    assert hit.standards == ["OWASP:A07", "CWE-1392"]


def test_postgres_default_credential_via_dsn_exposed_fires(tmp_path: Path) -> None:
    _compose(
        tmp_path,
        "services:\n  db:\n    image: postgres:16\n    ports:\n      - '5432:5432'\n"
        "  app:\n    image: myapp\n    environment:\n"
        "      DATABASE_URL: postgres://postgres:postgres@db:5432/app\n",
    )
    assert "default-service-credential/postgres-default-credential-exposed" in _rules(_run(tmp_path))


def test_postgres_default_credential_not_exposed_stays_silent(tmp_path: Path) -> None:
    # The exposure-scoping decision: a local-only default pair (no `ports:` publish) is a much
    # lower-risk case and intentionally out of scope for this guard.
    _compose(
        tmp_path,
        "services:\n  db:\n    image: postgres:16\n    environment:\n"
        "      POSTGRES_USER: postgres\n      POSTGRES_PASSWORD: postgres\n",
    )
    assert _rules(_run(tmp_path)) == set()


def test_postgres_loopback_bound_default_stays_silent(tmp_path: Path) -> None:
    # FP-bait: a loopback-only publish is the CORRECT pattern (mirrors compose-db-port-exposed).
    _compose(
        tmp_path,
        "services:\n  db:\n    image: postgres:16\n    ports:\n      - '127.0.0.1:5432:5432'\n"
        "    environment:\n      POSTGRES_USER: postgres\n      POSTGRES_PASSWORD: postgres\n",
    )
    assert _rules(_run(tmp_path)) == set()


def test_postgres_real_password_exposed_stays_silent(tmp_path: Path) -> None:
    # FP-bait: exposed + a real password must not fire.
    _compose(
        tmp_path,
        "services:\n  db:\n    image: postgres:16\n    ports:\n      - '5432:5432'\n"
        "    environment:\n      POSTGRES_USER: postgres\n      POSTGRES_PASSWORD: N7x!qLp2Zt\n",
    )
    assert _rules(_run(tmp_path)) == set()


# ── Grafana ───────────────────────────────────────────────────────────────────

def test_grafana_default_credential_explicit_fires(tmp_path: Path) -> None:
    _compose(
        tmp_path,
        "services:\n  grafana:\n    image: grafana/grafana\n    environment:\n"
        "      GF_SECURITY_ADMIN_USER: admin\n      GF_SECURITY_ADMIN_PASSWORD: admin\n",
    )
    findings = _run(tmp_path)
    hit = next(f for f in findings if f.rule == "default-service-credential/grafana-default-credential")
    assert hit.severity == "high"


def test_grafana_absent_admin_vars_fires_medium(tmp_path: Path) -> None:
    # Grafana's ACTUAL factory default when neither var is set — documented judgment call to
    # fire (at a lower confidence tier) rather than silently miss the common real case.
    _compose(tmp_path, "services:\n  grafana:\n    image: grafana/grafana:10.4.0\n")
    findings = _run(tmp_path)
    hit = next(
        f for f in findings if f.rule == "default-service-credential/grafana-implicit-default-credential"
    )
    assert hit.severity == "medium"


def test_grafana_custom_credential_stays_silent(tmp_path: Path) -> None:
    _compose(
        tmp_path,
        "services:\n  grafana:\n    image: grafana/grafana\n    environment:\n"
        "      GF_SECURITY_ADMIN_USER: opsadmin\n      GF_SECURITY_ADMIN_PASSWORD: Zx8!qRvT2m\n",
    )
    assert _rules(_run(tmp_path)) == set()


def test_grafana_partial_config_stays_silent(tmp_path: Path) -> None:
    # FP-bait for the absent-case: ONE var set (even to a non-default value) is ambiguous — the
    # other half may come from an env_file this guard cannot read — deliberately not flagged.
    _compose(
        tmp_path,
        "services:\n  grafana:\n    image: grafana/grafana\n    environment:\n"
        "      GF_SECURITY_ADMIN_USER: opsadmin\n",
    )
    assert _rules(_run(tmp_path)) == set()


def test_grafana_password_file_convention_stays_silent(tmp_path: Path) -> None:
    # Review M4, reproduced live: the hardened Docker-secrets convention
    # (GF_SECURITY_ADMIN_PASSWORD__FILE) was misread as "no admin-password var set" and flagged
    # as an implicit default credential -- inverting the signal on Grafana's OWN recommended
    # pattern.
    _compose(
        tmp_path,
        "services:\n  grafana:\n    image: grafana/grafana\n    environment:\n"
        "      GF_SECURITY_ADMIN_PASSWORD__FILE: /run/secrets/grafana_admin\n",
    )
    assert _rules(_run(tmp_path)) == set()


def test_grafana_user_file_convention_stays_silent(tmp_path: Path) -> None:
    _compose(
        tmp_path,
        "services:\n  grafana:\n    image: grafana/grafana\n    environment:\n"
        "      GF_SECURITY_ADMIN_USER__FILE: /run/secrets/grafana_user\n",
    )
    assert _rules(_run(tmp_path)) == set()


def test_grafana_absent_admin_vars_still_fires_without_file_convention(tmp_path: Path) -> None:
    # The counterweight: the __FILE widening must not swallow the real absent-credential case
    # this rule exists to catch.
    _compose(tmp_path, "services:\n  grafana:\n    image: grafana/grafana:10.4.0\n")
    assert "default-service-credential/grafana-implicit-default-credential" in _rules(_run(tmp_path))


def test_non_grafana_service_with_no_admin_vars_stays_silent(tmp_path: Path) -> None:
    # FP-bait: absence of GF_SECURITY_ADMIN_* is meaningless without an actual Grafana image.
    _compose(tmp_path, "services:\n  app:\n    image: myorg/myapp:1.0\n")
    assert _rules(_run(tmp_path)) == set()


# ── shared behavior: pragma / dev-compose / non-product / applies() ────────────

def test_pragma_silences_compose(tmp_path: Path) -> None:
    _compose(
        tmp_path,
        "# security: allow-default-service-credential\n"
        "services:\n  minio:\n    image: minio/minio\n    environment:\n"
        "      MINIO_ROOT_USER: minioadmin\n      MINIO_ROOT_PASSWORD: minioadmin\n",
    )
    assert _rules(_run(tmp_path)) == set()


def test_pragma_silences_env_file(tmp_path: Path) -> None:
    _env(
        tmp_path,
        "# security: allow-default-service-credential\n"
        "MINIO_ROOT_USER=minioadmin\nMINIO_ROOT_PASSWORD=minioadmin\n",
    )
    assert _rules(_run(tmp_path)) == set()


def test_dev_compose_file_stays_silent(tmp_path: Path) -> None:
    _compose(
        tmp_path,
        "services:\n  minio:\n    image: minio/minio\n    environment:\n"
        "      MINIO_ROOT_USER: minioadmin\n      MINIO_ROOT_PASSWORD: minioadmin\n",
        name="docker-compose.dev.yml",
    )
    assert _rules(_run(tmp_path)) == set()


def test_nonproduct_path_stays_silent(tmp_path: Path) -> None:
    fixtures = tmp_path / "tests" / "fixtures"
    fixtures.mkdir(parents=True)
    (fixtures / "docker-compose.yml").write_text(
        "services:\n  minio:\n    image: minio/minio\n    environment:\n"
        "      MINIO_ROOT_USER: minioadmin\n      MINIO_ROOT_PASSWORD: minioadmin\n",
        encoding="utf-8",
    )
    assert _rules(_run(tmp_path)) == set()


def test_not_applies_without_docker_feature() -> None:
    assert DefaultServiceCredentialGuard().applies(_ANY) is False


# ── adversarial: file-scoped pairing (documented design decision) ──────────────

def test_fires_when_pair_split_across_two_compose_services(tmp_path: Path) -> None:
    # Documented, deliberate consequence of file-scoped (not per-service-block) pairing: the
    # guard does not attribute a var to its owning service block, so two DIFFERENT services in
    # the SAME file that each carry one half of the default pair still fire. See the module
    # docstring "Detection: file-scoped pairing, not per-service-block" for the tradeoff.
    _compose(
        tmp_path,
        "services:\n"
        "  minio:\n    image: minio/minio\n    environment:\n"
        "      MINIO_ROOT_USER: minioadmin\n"
        "  other:\n    image: someorg/otherservice\n    environment:\n"
        "      MINIO_ROOT_PASSWORD: minioadmin\n",
    )
    assert "default-service-credential/minio-default-credential" in _rules(_run(tmp_path))


def test_pair_split_across_two_files_stays_silent(tmp_path: Path) -> None:
    # The opposite direction: no cross-FILE state is kept, so a pair split across two separate
    # files never fires — a documented false negative.
    _compose(
        tmp_path,
        "services:\n  minio:\n    image: minio/minio\n    environment:\n"
        "      MINIO_ROOT_USER: minioadmin\n",
        name="docker-compose.yml",
    )
    _env(tmp_path, "MINIO_ROOT_PASSWORD=minioadmin\n")
    # Neither file alone carries both halves, so no MinIO finding fires from either.
    assert "default-service-credential/minio-default-credential" not in _rules(_run(tmp_path))
