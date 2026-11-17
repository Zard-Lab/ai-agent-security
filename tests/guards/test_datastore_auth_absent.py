"""Tests for the datastore-auth-absent guard (§7).

Fires HIGH on a docker-compose Redis/MongoDB service with no authentication configured;
the defense-in-depth partner to compose-db-port-exposed (exposure).
"""
from __future__ import annotations

from agentsec.guards.datastore_auth_absent import DatastoreAuthAbsentGuard
from tests.guards._common import *  # noqa: F401,F403

_RULE = "datastore-auth-absent/no-authentication"


def _prof(tmp_path: Path):
    return mkprofile(tmp_path, features={"docker"})


def _run(tmp_path: Path):
    return DatastoreAuthAbsentGuard().run(tmp_path, _prof(tmp_path))


def _compose(tmp_path: Path, body: str, name: str = "docker-compose.yml") -> None:
    (tmp_path / name).write_text(body, encoding="utf-8")


# ── fires ─────────────────────────────────────────────────────────────────────

def test_redis_no_auth_fires(tmp_path: Path) -> None:
    _compose(tmp_path, "services:\n  redis:\n    image: redis:7\n")
    findings = _run(tmp_path)
    match = next(f for f in findings if f.rule == _RULE)
    assert match.severity == "high"
    assert match.check_id == "datastore-auth-absent"
    assert match.standards == ["OWASP:A05", "CIS:Docker"]
    assert "Redis" in match.title


def test_mongo_no_auth_fires(tmp_path: Path) -> None:
    _compose(tmp_path, "services:\n  mongo:\n    image: mongo:6\n")
    match = next(f for f in _run(tmp_path) if f.rule == _RULE)
    assert "MongoDB" in match.title


def test_bitnami_allow_empty_password_fires_even_with_password_env(tmp_path: Path) -> None:
    # ALLOW_EMPTY_PASSWORD=yes is an explicit auth-off switch — fire even though a REDIS_PASSWORD
    # is also present (Bitnami honours the empty-password flag).
    _compose(
        tmp_path,
        "services:\n  redis:\n    image: bitnami/redis:7\n    environment:\n"
        "      - ALLOW_EMPTY_PASSWORD=yes\n      - REDIS_PASSWORD=ignored\n",
    )
    assert any(f.rule == _RULE for f in _run(tmp_path))


def test_valkey_no_auth_fires(tmp_path: Path) -> None:
    # valkey is a redis fork and needs requirepass just the same.
    _compose(tmp_path, "services:\n  valkey:\n    image: valkey/valkey:8\n")
    assert any(f.rule == _RULE for f in _run(tmp_path))


def test_service_name_fallback_when_no_image_fires(tmp_path: Path) -> None:
    # A build-based service named `redis` with no image: still classified by name.
    _compose(tmp_path, "services:\n  redis:\n    build: ./redis\n")
    assert any(f.rule == _RULE for f in _run(tmp_path))


def test_two_services_only_the_unauthed_one_fires(tmp_path: Path) -> None:
    _compose(
        tmp_path,
        "services:\n"
        "  r1:\n    image: redis:7\n"
        "  r2:\n    image: redis:7\n    command: redis-server --requirepass p\n",
    )
    hits = [f for f in _run(tmp_path) if f.rule == _RULE]
    assert len(hits) == 1
    assert hits[0].location.endswith(":2")  # the r1 header line, not r2


# ── silent (FP-bait) ────────────────────────────────────────────────────────────

def test_redis_requirepass_command_silent(tmp_path: Path) -> None:
    _compose(
        tmp_path,
        "services:\n  redis:\n    image: redis:7\n    command: redis-server --requirepass secret\n",
    )
    assert [f for f in _run(tmp_path) if f.rule == _RULE] == []


def test_redis_password_env_silent(tmp_path: Path) -> None:
    _compose(
        tmp_path,
        "services:\n  cache:\n    image: bitnami/redis:7\n    environment:\n      - REDIS_PASSWORD=x\n",
    )
    assert [f for f in _run(tmp_path) if f.rule == _RULE] == []


def test_mongo_root_creds_silent(tmp_path: Path) -> None:
    _compose(
        tmp_path,
        "services:\n  mongo:\n    image: mongo:6\n    environment:\n"
        "      MONGO_INITDB_ROOT_USERNAME: admin\n      MONGO_INITDB_ROOT_PASSWORD: s\n",
    )
    assert [f for f in _run(tmp_path) if f.rule == _RULE] == []


def test_mongo_auth_flag_silent(tmp_path: Path) -> None:
    _compose(tmp_path, "services:\n  mongo:\n    image: mongo:6\n    command: mongod --auth\n")
    assert [f for f in _run(tmp_path) if f.rule == _RULE] == []


def test_postgres_out_of_scope_silent(tmp_path: Path) -> None:
    # Postgres/MySQL official images refuse to start without a password — not this guard's job.
    _compose(tmp_path, "services:\n  db:\n    image: postgres:16\n")
    assert [f for f in _run(tmp_path) if f.rule == _RULE] == []


def test_mongo_express_ui_not_flagged(tmp_path: Path) -> None:
    # mongo-express is a web UI (its own auth), not the datastore — must not be classified as mongo.
    _compose(tmp_path, "services:\n  mongo-express:\n    image: mongo-express:1\n")
    assert [f for f in _run(tmp_path) if f.rule == _RULE] == []


def test_pragma_silences(tmp_path: Path) -> None:
    _compose(
        tmp_path,
        "# security: allow-unauthenticated-datastore\nservices:\n  redis:\n    image: redis:7\n",
    )
    assert [f for f in _run(tmp_path) if f.rule == _RULE] == []


def test_redis_commander_ui_not_flagged(tmp_path: Path) -> None:
    # redis-commander is a web UI, not the datastore — must not be classified as redis (#358 review).
    _compose(tmp_path, "services:\n  rc:\n    image: rediscommander/redis-commander:latest\n")
    assert [f for f in _run(tmp_path) if f.rule == _RULE] == []


def test_not_applies_without_docker_feature() -> None:
    prof = mkprofile(Path("/tmp"), features={"python", "fastapi"})
    assert DatastoreAuthAbsentGuard().applies(prof) is False


# ── #358 review: false-negative fixes ───────────────────────────────────────────

def test_redis_password_env_ignored_on_official_image_fires(tmp_path: Path) -> None:
    # The official redis image never reads REDIS_PASSWORD — it does NOT authenticate the server, so
    # a vanilla `redis:7` with only that env is unauthenticated and must fire (#358 review High #1).
    _compose(tmp_path, "services:\n  redis:\n    image: redis:7\n    environment:\n      - REDIS_PASSWORD=x\n")
    assert any(f.rule == _RULE for f in _run(tmp_path))


def test_rediscli_auth_is_not_a_server_auth_signal_fires(tmp_path: Path) -> None:
    # REDISCLI_AUTH is a client-side redis-cli var, never read by redis-server (#358 review High #1).
    _compose(tmp_path, "services:\n  redis:\n    image: redis:7\n    environment:\n      - REDISCLI_AUTH=x\n")
    assert any(f.rule == _RULE for f in _run(tmp_path))


def test_commented_out_auth_token_still_fires(tmp_path: Path) -> None:
    # A commented-out token is not a real auth signal (#358 review High #2).
    _compose(tmp_path, "services:\n  redis:\n    image: redis:7\n    # TODO: add --requirepass and REDIS_PASSWORD\n")
    assert any(f.rule == _RULE for f in _run(tmp_path))


def test_empty_password_value_still_fires(tmp_path: Path) -> None:
    # An explicitly-empty password is the misconfiguration this guard exists for (#358 review Medium #3).
    _compose(
        tmp_path,
        "services:\n  mongo:\n    image: mongo:6\n    environment:\n      MONGO_INITDB_ROOT_PASSWORD:\n",
    )
    assert any(f.rule == _RULE for f in _run(tmp_path))


def test_digest_pinned_image_classified_fires(tmp_path: Path) -> None:
    # A digest-pinned datastore must still be recognized (#358 review Low #5).
    _compose(tmp_path, "services:\n  redis:\n    image: redis@sha256:abc123\n")
    assert any(f.rule == _RULE for f in _run(tmp_path))


def test_quoted_empty_password_still_fires(tmp_path: Path) -> None:
    # A quoted empty string is still no password — the opening quote must not read as "value present"
    # (#358 re-review Medium).
    _compose(
        tmp_path,
        'services:\n  mongo:\n    image: mongo:6\n    environment:\n      MONGO_INITDB_ROOT_PASSWORD: ""\n',
    )
    assert any(f.rule == _RULE for f in _run(tmp_path))


def test_hash_in_quoted_password_value_not_clipped(tmp_path: Path) -> None:
    # A `#` inside a quoted password is part of the value, not a comment — must NOT be clipped to empty,
    # so a real password containing `#` stays silent (#358 re-review; YAML-aware comment stripping).
    _compose(
        tmp_path,
        'services:\n  mongo:\n    image: mongo:6\n    environment:\n      MONGO_INITDB_ROOT_PASSWORD: "a#b"\n',
    )
    assert [f for f in _run(tmp_path) if f.rule == _RULE] == []


# ── #359: flow-mapping services + mongo images without a `mongo` path segment ────

def test_flow_mapping_redis_no_auth_fires(tmp_path: Path) -> None:
    # A one-line flow-mapping service was invisible to the block-only parser (#359 Gap 1).
    _compose(tmp_path, 'services:\n  redis: {image: "redis:7"}\n')
    match = next(f for f in _run(tmp_path) if f.rule == _RULE)
    assert "Redis" in match.title
    assert match.location.endswith(":2")  # the flow header line


def test_flow_mapping_classified_by_image_not_name_fires(tmp_path: Path) -> None:
    # The inline `image:` is parsed (not just the service-name fallback): a service named `cache`
    # is still classified as redis by its flow-mapping image (#359 Gap 1).
    _compose(tmp_path, 'services:\n  cache: {image: "redis:7"}\n')
    assert any(f.rule == _RULE for f in _run(tmp_path))


def test_flow_mapping_with_requirepass_silent(tmp_path: Path) -> None:
    # An auth token living inside the flow mapping is detected — no false-positive (#359 Gap 1).
    _compose(
        tmp_path,
        'services:\n  redis: {image: "redis:7", command: "redis-server --requirepass secret"}\n',
    )
    assert [f for f in _run(tmp_path) if f.rule == _RULE] == []


def test_flow_mapping_service_alongside_block_service(tmp_path: Path) -> None:
    # A flow service must not swallow, nor be swallowed by, an adjacent block service (#359 Gap 1).
    _compose(
        tmp_path,
        'services:\n  redis: {image: "redis:7"}\n  mongo:\n    image: mongo:6\n',
    )
    hits = [f for f in _run(tmp_path) if f.rule == _RULE]
    assert len(hits) == 2
    assert {"Redis", "MongoDB"} == {"Redis" if "Redis" in f.title else "MongoDB" for f in hits}


def test_multiline_flow_mapping_with_requirepass_silent(tmp_path: Path) -> None:
    # #375 review: a MULTI-line flow-mapping `redis: {` with a real --requirepass on a following
    # line was an ACTIVE false positive — the flat parser emitted an empty body for the canonical
    # `redis` name and fired "no auth" while the token sat below. It must now stay silent (the
    # multi-line flow is unscanned, not mis-flagged).
    _compose(
        tmp_path,
        "services:\n"
        "  redis: {\n"
        '    image: "redis:7",\n'
        '    command: redis-server --requirepass "secret"\n'
        "  }\n",
    )
    assert [f for f in _run(tmp_path) if f.rule == _RULE] == []


def test_multiline_flow_mapping_mongo_with_auth_silent(tmp_path: Path) -> None:
    # Same class, MongoDB: a multi-line flow header on the canonical `mongo` name with real
    # MONGO_INITDB_ROOT_PASSWORD below must not fire (#375 review).
    _compose(
        tmp_path,
        "services:\n"
        "  mongo: {\n"
        '    image: "mongo:6",\n'
        '    environment: {MONGO_INITDB_ROOT_USERNAME: "root", MONGO_INITDB_ROOT_PASSWORD: "pw"}\n'
        "  }\n",
    )
    assert [f for f in _run(tmp_path) if f.rule == _RULE] == []


def test_multiline_flow_mapping_no_auth_is_unscanned(tmp_path: Path) -> None:
    # The disclosed flip side: because a multi-line flow mapping is not assembled, a genuinely
    # passwordless one is a false-NEGATIVE miss (unscanned), NOT a false positive. Locked so the
    # "unscanned" contract is explicit and can't silently flip back to an FP (#375 review).
    _compose(
        tmp_path,
        "services:\n"
        "  redis: {\n"
        '    image: "redis:7"\n'
        "  }\n",
    )
    assert [f for f in _run(tmp_path) if f.rule == _RULE] == []


def test_mongodb_community_server_name_without_mongo_segment_fires(tmp_path: Path) -> None:
    # A private re-tag keeps the NAME `mongodb-community-server` but not the `mongodb` org segment;
    # it must still be classified as mongo (#359 Gap 2).
    _compose(tmp_path, "services:\n  db:\n    image: someorg/mongodb-community-server:7\n")
    match = next(f for f in _run(tmp_path) if f.rule == _RULE)
    assert "MongoDB" in match.title


def test_mongodb_exporter_not_flagged(tmp_path: Path) -> None:
    # `mongodb-exporter` is a metrics exporter, not the datastore — the `-` terminator keeps it
    # outside the widened mongo image match (#359 Gap 2 FP boundary).
    _compose(tmp_path, "services:\n  metrics:\n    image: someorg/mongodb-exporter:1\n")
    assert [f for f in _run(tmp_path) if f.rule == _RULE] == []


def test_flow_mapping_mongodb_community_server_fires(tmp_path: Path) -> None:
    # Gap 1 x Gap 2 together: a name-only mongo image (no `mongo` path segment) written in
    # flow-mapping style must still be discovered AND classified as mongo (#359).
    _compose(tmp_path, 'services:\n  db: {image: "someorg/mongodb-community-server:7"}\n')
    match = next(f for f in _run(tmp_path) if f.rule == _RULE)
    assert "MongoDB" in match.title


def test_datastore_auth_absent_skips_dev_compose(tmp_path: Path) -> None:
    # §H.2: a `*.dev.yml` compose is a local-development env — an unauthenticated loopback
    # datastore there is conventional. The prod/base compose still fires.
    _compose(tmp_path, "services:\n  redis:\n    image: redis:7\n", name="docker-compose.dev.yml")
    assert DatastoreAuthAbsentGuard().run(tmp_path, _prof(tmp_path)) == []


def test_datastore_auth_absent_still_fires_on_base_compose(tmp_path: Path) -> None:
    _compose(tmp_path, "services:\n  redis:\n    image: redis:7\n", name="docker-compose.yml")
    assert any(f.rule == _RULE for f in DatastoreAuthAbsentGuard().run(tmp_path, _prof(tmp_path)))


# ── a line past 1 KB is comment-stripped like any other (#508) ────────────────
# `strip_hash_comments` used to skip its quote mask past 1 KB and hand the line back with its
# comment attached, so an auth flag written only in that comment counted as configured auth.
_LONG_FLAGS = "--save 60 1 " * 90  # ~1.1 KB of real flags: no `#`, no quotes


def test_long_command_line_comment_only_requirepass_fires(tmp_path: Path) -> None:
    _compose(
        tmp_path,
        "services:\n  redis:\n    image: redis:7\n"
        f'    command: redis-server {_LONG_FLAGS}# --requirepass "x"\n',
    )
    assert any(f.rule == _RULE for f in _run(tmp_path))


def test_long_command_line_quoted_hash_before_real_requirepass_silent(tmp_path: Path) -> None:
    # FP-bait for that widening: the long line is now quote-masked, not cut at the first ` #`, so a
    # `#` inside an earlier quoted value does not clip the real `--requirepass` after it.
    _compose(
        tmp_path,
        "services:\n  redis:\n    image: redis:7\n"
        f'    command: redis-server --logfile "/data/redis #1.log" {_LONG_FLAGS}--requirepass secret\n',
    )
    assert _run(tmp_path) == []
