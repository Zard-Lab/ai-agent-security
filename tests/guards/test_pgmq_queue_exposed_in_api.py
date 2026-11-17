from __future__ import annotations

from agentsec.guards.pgmq_queue_exposed_in_api import PgmqQueueExposedInApiGuard
from tests.guards._common import *  # noqa: F401,F403


def _pgmq_prof(root: Path) -> StackProfile:
    return mkprofile(root, features={"supabase"})


def test_pgmq_queue_exposed_fires_when_schema_listed(tmp_path: Path) -> None:
    (tmp_path / "supabase").mkdir()
    (tmp_path / "supabase" / "config.toml").write_text(
        '[api]\nschemas = ["public", "pgmq_public"]\n',
        encoding="utf-8",
    )
    findings = PgmqQueueExposedInApiGuard().run(tmp_path, _pgmq_prof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "pgmq-queue-exposed-in-api/schema-exposed"
    assert findings[0].severity == "high"


def test_pgmq_queue_silent_without_pgmq_public_in_schemas(tmp_path: Path) -> None:
    # FP-bait: a normal Supabase config exposing only `public` — must stay silent.
    (tmp_path / "supabase").mkdir()
    (tmp_path / "supabase" / "config.toml").write_text(
        '[api]\nschemas = ["public", "graphql_public"]\n',
        encoding="utf-8",
    )
    assert PgmqQueueExposedInApiGuard().run(tmp_path, _pgmq_prof(tmp_path)) == []


def test_pgmq_queue_silent_without_api_table(tmp_path: Path) -> None:
    # A config.toml with no [api] table at all (e.g. only [db]) — must stay silent,
    # not crash on a missing key.
    (tmp_path / "supabase").mkdir()
    (tmp_path / "supabase" / "config.toml").write_text(
        '[db]\nport = 54322\n',
        encoding="utf-8",
    )
    assert PgmqQueueExposedInApiGuard().run(tmp_path, _pgmq_prof(tmp_path)) == []


def test_pgmq_queue_pragma_silences(tmp_path: Path) -> None:
    (tmp_path / "supabase").mkdir()
    (tmp_path / "supabase" / "config.toml").write_text(
        '# security: allow-pgmq-queue-exposed\n'
        '[api]\nschemas = ["public", "pgmq_public"]\n',
        encoding="utf-8",
    )
    assert PgmqQueueExposedInApiGuard().run(tmp_path, _pgmq_prof(tmp_path)) == []


def test_pgmq_queue_ignores_malformed_toml(tmp_path: Path) -> None:
    # A syntactically broken config.toml must not crash the guard.
    (tmp_path / "supabase").mkdir()
    (tmp_path / "supabase" / "config.toml").write_text(
        "[api\nschemas = not valid toml at all ][[",
        encoding="utf-8",
    )
    assert PgmqQueueExposedInApiGuard().run(tmp_path, _pgmq_prof(tmp_path)) == []


def test_pgmq_queue_not_applicable_without_supabase() -> None:
    prof = mkprofile(Path("/tmp"), features={"python"})
    assert not PgmqQueueExposedInApiGuard().applies(prof)


def test_pgmq_queue_pragma_quoted_in_a_toml_string_does_not_suppress(tmp_path: Path) -> None:
    # #424 E2: the documented `# security: …` form inside a TOML string is content, not a comment.
    (tmp_path / "supabase").mkdir()
    (tmp_path / "supabase" / "config.toml").write_text(
        '[api]\nschemas = ["public", "pgmq_public"]\n'
        'note = "opt out with # security: allow-pgmq-queue-exposed"\n',
        encoding="utf-8",
    )
    assert len(PgmqQueueExposedInApiGuard().run(tmp_path, _pgmq_prof(tmp_path))) == 1
