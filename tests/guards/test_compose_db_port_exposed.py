"""Tests for the compose-db-port-exposed guard (§6c, §12)."""
from __future__ import annotations

from agentsec.guards.compose_db_port_exposed import ComposeDbPortExposedGuard
from tests.guards._common import *  # noqa: F401,F403

_RULE = "compose-db-port-exposed/datastore-port-published"


def _prof(tmp_path: Path):
    return mkprofile(tmp_path, features={"docker"})


def _run(tmp_path: Path):
    return ComposeDbPortExposedGuard().run(tmp_path, _prof(tmp_path))


def _compose(tmp_path: Path, body: str, name: str = "docker-compose.yml") -> None:
    (tmp_path / name).write_text(body, encoding="utf-8")


# ── fires ─────────────────────────────────────────────────────────────────────

def test_compose_db_port_postgres_exposed_fires(tmp_path: Path) -> None:
    """A plain 5432:5432 publish on Postgres must fire (the canonical case)."""
    _compose(tmp_path, "services:\n  db:\n    image: postgres:16\n    ports:\n      - '5432:5432'\n")
    findings = _run(tmp_path)
    assert any(f.rule == _RULE for f in findings)
    match = next(f for f in findings if f.rule == _RULE)
    assert match.severity == "critical"
    assert match.check_id == "compose-db-port-exposed"
    assert match.standards == ["OWASP:A05", "CIS:Docker"]


def test_compose_db_port_0000_fires(tmp_path: Path) -> None:
    """Explicit 0.0.0.0:5432:5432 must fire."""
    _compose(tmp_path, "services:\n  db:\n    image: postgres\n    ports:\n      - '0.0.0.0:5432:5432'\n")
    assert any(f.rule == _RULE for f in _run(tmp_path))


def test_compose_db_port_remap_fires(tmp_path: Path) -> None:
    """15432:5432 publishes the Postgres CONTAINER port on a remapped host port — must fire."""
    _compose(tmp_path, "services:\n  db:\n    image: postgres\n    ports:\n      - '15432:5432'\n")
    assert len([f for f in _run(tmp_path) if f.rule == _RULE]) == 1


def test_compose_db_port_redis_fires(tmp_path: Path) -> None:
    """Redis 6379 exposed must fire."""
    _compose(tmp_path, "services:\n  cache:\n    image: redis\n    ports:\n      - '6379:6379'\n")
    assert any(f.rule == _RULE for f in _run(tmp_path))


def test_compose_db_port_bare_form_fires(tmp_path: Path) -> None:
    """Bare '5432' (container-only) publishes to all interfaces — must fire."""
    _compose(tmp_path, "services:\n  db:\n    image: postgres\n    ports:\n      - '5432'\n")
    assert any(f.rule == _RULE for f in _run(tmp_path))


# ── silent (FP-bait) ────────────────────────────────────────────────────────────

def test_compose_db_port_localhost_silent(tmp_path: Path) -> None:
    """127.0.0.1:5432:5432 loopback bind is the correct pattern — must NOT fire."""
    _compose(tmp_path, "services:\n  db:\n    image: postgres\n    ports:\n      - '127.0.0.1:5432:5432'\n")
    assert [f for f in _run(tmp_path) if f.rule == _RULE] == []


def test_compose_db_port_non_db_silent(tmp_path: Path) -> None:
    """A web port (8080) is not a datastore — must NOT fire (FP-bait)."""
    _compose(tmp_path, "services:\n  web:\n    image: nginx\n    ports:\n      - '8080:8080'\n")
    assert [f for f in _run(tmp_path) if f.rule == _RULE] == []


def test_compose_db_nondb_container_silent(tmp_path: Path) -> None:
    """5432:80 publishes a WEB container (port 80) on host port 5432 — container is not a
    datastore, so it must NOT fire (the container port is the service identity)."""
    _compose(tmp_path, "services:\n  web:\n    image: nginx\n    ports:\n      - '5432:80'\n")
    assert [f for f in _run(tmp_path) if f.rule == _RULE] == []


def test_compose_db_port_outside_ports_block_silent(tmp_path: Path) -> None:
    """A 5432:5432-looking value in environment (not ports:) must NOT fire."""
    _compose(tmp_path, "services:\n  db:\n    image: postgres\n    environment:\n      - RANGE=5432:5432\n")
    assert [f for f in _run(tmp_path) if f.rule == _RULE] == []


def test_compose_db_port_pragma_silences(tmp_path: Path) -> None:
    """The allow-pragma must suppress all findings for that file (intentional exposure)."""
    _compose(
        tmp_path,
        "# security: allow-exposed-db-port\n"
        "services:\n  db:\n    image: postgres\n    ports:\n      - '5432:5432'\n",
    )
    assert _run(tmp_path) == []


# ── applies() gate ──────────────────────────────────────────────────────────────

def test_compose_db_port_applies_gate(tmp_path: Path) -> None:
    """Gated on the docker feature."""
    g = ComposeDbPortExposedGuard()
    assert g.applies(mkprofile(tmp_path, features={"docker"})) is True
    assert g.applies(mkprofile(tmp_path, features={"python"})) is False


def test_compose_db_no_compose_silent(tmp_path: Path) -> None:
    """No compose file -> no findings."""
    (tmp_path / "app.py").write_text("print('hi')\n", encoding="utf-8")
    assert _run(tmp_path) == []


def test_compose_db_port_inline_comment_fires(tmp_path: Path) -> None:
    """An inline YAML comment on the port entry must not hide the exposure (review #246)."""
    _compose(tmp_path, "services:\n  db:\n    image: postgres:16\n    ports:\n      - '5432:5432'  # dev only\n")
    assert any(f.rule == _RULE for f in _run(tmp_path))


# ── known false-negatives (conservative seed — documented in the design doc) ────

def test_compose_db_port_tcp_suffix_known_fn(tmp_path: Path) -> None:
    """`/tcp` protocol suffix is a known FN: the port regex excludes `/`, so it is not
    parsed. Deliberate conservative-seed limitation, not an oversight."""
    _compose(tmp_path, "services:\n  db:\n    image: postgres\n    ports:\n      - '5432:5432/tcp'\n")
    assert [f for f in _run(tmp_path) if f.rule == _RULE] == []


def test_compose_db_port_ipv6_bracket_host_known_fn(tmp_path: Path) -> None:
    """A bracketed IPv6 host bind (e.g. `[::]:5432:5432`) is a known FN: split(':') yields
    >3 parts, so the entry is skipped. Deliberate conservative-seed limitation."""
    _compose(tmp_path, "services:\n  db:\n    image: postgres\n    ports:\n      - '[::]:5432:5432'\n")
    assert [f for f in _run(tmp_path) if f.rule == _RULE] == []


# ── long-syntax ports (#356) ─────────────────────────────────────────────────────

_LONG = "services:\n  db:\n    image: postgres:16\n    ports:\n"


def test_long_syntax_host_ip_0000_fires(tmp_path: Path) -> None:
    _compose(tmp_path, _LONG + "      - target: 5432\n        published: 5432\n        host_ip: 0.0.0.0\n        protocol: tcp\n")
    assert any(f.rule == _RULE for f in _run(tmp_path))


def test_long_syntax_host_ip_omitted_fires(tmp_path: Path) -> None:
    # An omitted host_ip defaults to 0.0.0.0 in docker-compose — exposed, must fire.
    _compose(tmp_path, _LONG + "      - target: 6379\n        published: 6379\n")
    assert any(f.rule == _RULE for f in _run(tmp_path))


def test_long_syntax_flow_map_fires(tmp_path: Path) -> None:
    _compose(tmp_path, _LONG + "      - {target: 5432, published: 5432, host_ip: 0.0.0.0}\n")
    assert any(f.rule == _RULE for f in _run(tmp_path))


def test_long_syntax_mixed_with_short_both_evaluated(tmp_path: Path) -> None:
    _compose(tmp_path, _LONG + "      - '5432:5432'\n      - target: 6379\n        host_ip: 0.0.0.0\n")
    assert len([f for f in _run(tmp_path) if f.rule == _RULE]) == 2


def test_long_syntax_flushes_at_service_boundary(tmp_path: Path) -> None:
    # A long-syntax entry immediately followed by the next service must still be evaluated.
    _compose(tmp_path, _LONG + "      - target: 27017\n        host_ip: 0.0.0.0\n  web:\n    image: nginx\n")
    assert any(f.rule == _RULE for f in _run(tmp_path))


def test_long_syntax_host_ip_loopback_silent(tmp_path: Path) -> None:
    _compose(tmp_path, _LONG + "      - target: 5432\n        published: 5432\n        host_ip: 127.0.0.1\n")
    assert [f for f in _run(tmp_path) if f.rule == _RULE] == []


def test_long_syntax_non_datastore_target_silent(tmp_path: Path) -> None:
    _compose(tmp_path, _LONG + "      - target: 8080\n        published: 8080\n        host_ip: 0.0.0.0\n")
    assert [f for f in _run(tmp_path) if f.rule == _RULE] == []


def test_long_syntax_loopback_host_ip_with_comment_silent(tmp_path: Path) -> None:
    # #360 review (High FP): a comment on the host_ip continuation line must be stripped, else the
    # loopback bind fails the anchored match and fires a spurious CRITICAL.
    _compose(tmp_path, _LONG + "      - target: 5432\n        host_ip: 127.0.0.1  # loopback only\n")
    assert [f for f in _run(tmp_path) if f.rule == _RULE] == []


def test_long_syntax_public_host_ip_with_comment_fires(tmp_path: Path) -> None:
    _compose(tmp_path, _LONG + "      - target: 5432\n        host_ip: 0.0.0.0  # public\n")
    assert any(f.rule == _RULE for f in _run(tmp_path))


def test_long_syntax_nested_host_ip_not_absorbed_fires(tmp_path: Path) -> None:
    # #360 review (Medium FN): a `host_ip:` nested deeper (under an unrelated `labels:` map) is not
    # this entry's field — it must not be absorbed, so the entry (no real host_ip) still fires.
    _compose(
        tmp_path,
        _LONG + "      - target: 5432\n        published: 5432\n        labels:\n          host_ip: 127.0.0.1\n",
    )
    assert any(f.rule == _RULE for f in _run(tmp_path))


# ── admin/broker port extension (#4, DockSec batch) ─────────────────────────────

_ADMIN_RULE = "compose-db-port-exposed/admin-broker-port-published"


def test_rabbitmq_management_port_exposed_fires_high(tmp_path: Path) -> None:
    """RabbitMQ management UI (15672) exposed non-loopback must fire HIGH, not CRITICAL."""
    _compose(tmp_path, "services:\n  mq:\n    image: rabbitmq:3-management\n    ports:\n      - '15672:15672'\n")
    findings = _run(tmp_path)
    match = next(f for f in findings if f.rule == _ADMIN_RULE)
    assert match.severity == "high"
    assert match.check_id == "compose-db-port-exposed"


def test_kafka_broker_port_exposed_fires(tmp_path: Path) -> None:
    _compose(tmp_path, "services:\n  kafka:\n    image: bitnami/kafka\n    ports:\n      - '9092:9092'\n")
    assert any(f.rule == _ADMIN_RULE for f in _run(tmp_path))


def test_etcd_client_and_peer_ports_fire(tmp_path: Path) -> None:
    _compose(
        tmp_path,
        "services:\n  etcd:\n    image: bitnami/etcd\n    ports:\n"
        "      - '2379:2379'\n      - '2380:2380'\n",
    )
    assert len([f for f in _run(tmp_path) if f.rule == _ADMIN_RULE]) == 2


def test_consul_http_api_port_fires(tmp_path: Path) -> None:
    _compose(tmp_path, "services:\n  consul:\n    image: consul\n    ports:\n      - '8500:8500'\n")
    assert any(f.rule == _ADMIN_RULE for f in _run(tmp_path))


def test_kibana_dashboard_port_fires(tmp_path: Path) -> None:
    _compose(tmp_path, "services:\n  kibana:\n    image: kibana\n    ports:\n      - '5601:5601'\n")
    assert any(f.rule == _ADMIN_RULE for f in _run(tmp_path))


def test_admin_broker_port_loopback_silent(tmp_path: Path) -> None:
    """FP-bait: a loopback bind on an admin/broker port is the correct pattern too."""
    _compose(tmp_path, "services:\n  mq:\n    image: rabbitmq:3-management\n    ports:\n      - '127.0.0.1:15672:15672'\n")
    assert [f for f in _run(tmp_path) if f.rule == _ADMIN_RULE] == []


def test_admin_broker_port_pragma_silences(tmp_path: Path) -> None:
    _compose(
        tmp_path,
        "# security: allow-exposed-db-port\n"
        "services:\n  mq:\n    image: rabbitmq:3-management\n    ports:\n      - '15672:15672'\n",
    )
    assert _run(tmp_path) == []


def test_admin_broker_ports_do_not_overlap_datastore_ports() -> None:
    """Structural guardrail: adding new admin/broker ports must never collide with an
    existing datastore port entry (the two tiers carry different severities)."""
    from agentsec.guards.compose_db_port_exposed import _ADMIN_BROKER_PORTS, _DB_PORTS
    assert set(_DB_PORTS) & set(_ADMIN_BROKER_PORTS) == set()


def test_dev_compose_is_out_of_scope_like_its_mirror(tmp_path: Path) -> None:
    # #484 review: this guard fired on a `*.dev.yml` while its stated mirror
    # `datastore-auth-absent` suppressed on the same file — the report said the Redis port was
    # published while hiding that it had no password, which reads as more reassuring than either
    # answer alone. Both now use the shared `is_dev_compose_file`, incl. the hyphen spelling.
    compose = (
        "services:\n"
        "  redis:\n"
        "    image: redis:7\n"
        "    ports:\n"
        '      - "6379:6379"\n'
    )
    profile = mkprofile(tmp_path, features={"docker"})
    for name in ("docker-compose.dev.yml", "docker-compose-dev.yml", "docker-compose.local.yml"):
        (tmp_path / name).write_text(compose, encoding="utf-8")
        assert ComposeDbPortExposedGuard().run(tmp_path, profile) == [], name
        (tmp_path / name).unlink()
    # ...and a base/prod compose still fires, so the skip did not swallow the rule.
    (tmp_path / "docker-compose.yml").write_text(compose, encoding="utf-8")
    assert ComposeDbPortExposedGuard().run(tmp_path, profile) != []


# ── a ports entry past 1 KB is comment-stripped like any other (#508) ─────────
# Past 1 KB `strip_hash_comments` used to return the entry with its comment attached, so the
# anchored whole-value match failed and the entry was never evaluated: a silent Critical.
_LONG_NOTE = "kept open for the reporting job " * 35  # ~1.1 KB, no `#`, no quotes


def test_compose_db_port_entry_with_long_comment_fires(tmp_path: Path) -> None:
    _compose(
        tmp_path,
        f'services:\n  db:\n    image: postgres:16\n    ports:\n      - "5432:5432"  # {_LONG_NOTE}\n',
    )
    match = next(f for f in _run(tmp_path) if f.rule == _RULE)
    assert match.severity == "critical"


def test_compose_db_port_loopback_entry_with_long_comment_silent(tmp_path: Path) -> None:
    # FP-bait for that widening: the long entry is now parsed, so its loopback bind must be read.
    _compose(
        tmp_path,
        "services:\n  db:\n    image: postgres:16\n    ports:\n"
        f'      - "127.0.0.1:5432:5432"  # {_LONG_NOTE}\n',
    )
    assert _run(tmp_path) == []
