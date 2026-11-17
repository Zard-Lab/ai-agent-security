from __future__ import annotations

import json

from agentsec.guards.empty_password_in_config import EmptyPasswordInConfigGuard
from tests.guards._common import *  # noqa: F401,F403


def _run(tmp_path: Path) -> list:
    return EmptyPasswordInConfigGuard().run(tmp_path, mkprofile(tmp_path))


# ── planted violations ───────────────────────────────────────────────────────

def test_fires_on_empty_password_json_top_level(tmp_path: Path) -> None:
    (tmp_path / "config.json").write_text(
        json.dumps({"username": "admin", "password": ""}), encoding="utf-8"
    )
    findings = _run(tmp_path)
    assert len(findings) == 1
    assert findings[0].rule == "empty-password-in-config/empty-password"
    assert findings[0].severity == "high"
    assert findings[0].check_id == "empty-password-in-config"


def test_fires_on_empty_password_json_deeply_nested(tmp_path: Path) -> None:
    # Adversarial bypass check: a deeply nested JSON structure (object under object under object)
    # must still be caught — a shallow (top-level-only) walk would miss this.
    cfg = {"database": {"credentials": {"password": ""}}}
    (tmp_path / "settings.json").write_text(json.dumps(cfg), encoding="utf-8")
    findings = _run(tmp_path)
    assert len(findings) == 1
    assert "database.credentials.password" in findings[0].message


def test_fires_on_empty_password_json_inside_array_of_objects(tmp_path: Path) -> None:
    cfg = {"services": [{"name": "a"}, {"name": "b", "auth": {"password": ""}}]}
    (tmp_path / "services.json").write_text(json.dumps(cfg), encoding="utf-8")
    findings = _run(tmp_path)
    assert len(findings) == 1


def test_fires_on_empty_password_yaml_no_value(tmp_path: Path) -> None:
    (tmp_path / "config.yaml").write_text(
        "username: admin\npassword:\nhost: db.internal\n", encoding="utf-8"
    )
    findings = _run(tmp_path)
    assert len(findings) == 1
    assert findings[0].rule == "empty-password-in-config/empty-password"
    assert findings[0].severity == "high"
    assert findings[0].location == "config.yaml:2"


def test_fires_on_empty_password_yaml_explicit_empty_string(tmp_path: Path) -> None:
    (tmp_path / "config.yml").write_text('password: ""\n', encoding="utf-8")
    findings = _run(tmp_path)
    assert len(findings) == 1


def test_fires_on_empty_password_yaml_bare_at_eof(tmp_path: Path) -> None:
    # Bare `password:` as the very last line in the file (nothing follows at all) is still a
    # genuine empty/null scalar, not a nested mapping — must fire.
    (tmp_path / "config.yaml").write_text("username: admin\npassword:", encoding="utf-8")
    findings = _run(tmp_path)
    assert len(findings) == 1
    assert findings[0].location == "config.yaml:2"


def test_fires_on_empty_password_yaml_bare_followed_by_sibling_key(tmp_path: Path) -> None:
    # Bare `password:` nested under another key, immediately followed by a SAME-indent sibling
    # key — not a nested mapping (nothing is more indented under it) — must fire.
    (tmp_path / "config.yaml").write_text(
        "credentials:\n  username: admin\n  password:\n  timeout: 30\n", encoding="utf-8"
    )
    findings = _run(tmp_path)
    assert len(findings) == 1
    assert findings[0].location == "config.yaml:3"


# ── FP-bait ───────────────────────────────────────────────────────────────────

def test_silent_on_nonempty_password_json(tmp_path: Path) -> None:
    (tmp_path / "config.json").write_text(
        json.dumps({"username": "admin", "password": "hunter2"}), encoding="utf-8"
    )
    assert _run(tmp_path) == []


def test_silent_on_nonempty_password_yaml(tmp_path: Path) -> None:
    (tmp_path / "config.yaml").write_text("password: hunter2\n", encoding="utf-8")
    assert _run(tmp_path) == []


def test_silent_on_nonproduct_path(tmp_path: Path) -> None:
    # FP-bait: a path is_nonproduct_path() already excludes (tests/fixtures/...) must not fire,
    # even with a real planted violation inside it.
    fixtures = tmp_path / "tests" / "fixtures"
    fixtures.mkdir(parents=True)
    (fixtures / "config.json").write_text(json.dumps({"password": ""}), encoding="utf-8")
    assert _run(tmp_path) == []


def test_silent_on_package_json_even_with_empty_string_value(tmp_path: Path) -> None:
    # FP-bait: package.json is excluded defensively for the JSON case, regardless of content —
    # dependency blocks are version strings, never password fields, but excluded anyway.
    (tmp_path / "package.json").write_text(
        json.dumps({"name": "app", "version": "", "password": ""}), encoding="utf-8"
    )
    assert _run(tmp_path) == []


def test_silent_on_key_name_password_placeholder(tmp_path: Path) -> None:
    # Adversarial bypass check: only the EXACT key name "password" (case-insensitive) should
    # ever match — a substring like "password_placeholder"/"password_hint" must not fire.
    cfg = {"password_placeholder": "", "password_hint": ""}
    (tmp_path / "config.json").write_text(json.dumps(cfg), encoding="utf-8")
    assert _run(tmp_path) == []


def test_silent_on_locale_path_yaml(tmp_path: Path) -> None:
    locale_dir = tmp_path / "locales" / "en"
    locale_dir.mkdir(parents=True)
    (locale_dir / "strings.yaml").write_text("password: \n", encoding="utf-8")
    assert _run(tmp_path) == []


def test_pragma_suppresses_yaml(tmp_path: Path) -> None:
    (tmp_path / "config.yaml").write_text(
        "# security: allow-empty-password-in-config\npassword:\n", encoding="utf-8"
    )
    assert _run(tmp_path) == []


def test_silent_on_openapi_schema_property_password(tmp_path: Path) -> None:
    # FP-bait (#548 Critical 1): `password:` opening a nested OpenAPI schema property
    # mapping is NOT an empty-string value — the next line is more deeply indented, so this is a
    # mapping, not a scalar. Must not fire.
    (tmp_path / "openapi.yaml").write_text(
        "properties:\n  password:\n    type: string\n    format: password\n", encoding="utf-8"
    )
    assert _run(tmp_path) == []


def test_silent_on_helm_values_secret_ref_password(tmp_path: Path) -> None:
    # FP-bait (#548 Critical 1): a Helm values.yaml `password:` key whose value is a
    # nested `valueFrom.secretKeyRef` mapping (the standard "don't put the secret in this file,
    # reference a Secret object instead" pattern) is NOT an empty-string value. Must not fire.
    (tmp_path / "values.yaml").write_text(
        "password:\n"
        "  valueFrom:\n"
        "    secretKeyRef:\n"
        "      name: db-secret\n"
        "      key: password\n",
        encoding="utf-8",
    )
    assert _run(tmp_path) == []
