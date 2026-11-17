from __future__ import annotations

from agentsec.guards.rate_limit_no_persistent_store import RateLimitNoPersistentStoreGuard
from tests.guards._common import *  # noqa: F401,F403


def test_rate_limit_no_persistent_store_fires_no_storage_uri(tmp_path: Path) -> None:
    (tmp_path / "limiter.py").write_text(
        "from slowapi import Limiter\nfrom slowapi.util import get_remote_address\n"
        "limiter = Limiter(key_func=get_remote_address)\n",
        encoding="utf-8",
    )
    findings = RateLimitNoPersistentStoreGuard().run(tmp_path, _python_nodirs_prof(tmp_path))
    assert any(f.rule == "rate-limit-no-persistent-store/no-persistent-store" for f in findings)


def test_rate_limit_no_persistent_store_fires_explicit_memory_uri(tmp_path: Path) -> None:
    (tmp_path / "limiter.py").write_text(
        "from slowapi import Limiter\nfrom slowapi.util import get_remote_address\n"
        "limiter = Limiter(key_func=get_remote_address, storage_uri='memory://')\n",
        encoding="utf-8",
    )
    findings = RateLimitNoPersistentStoreGuard().run(tmp_path, _python_nodirs_prof(tmp_path))
    assert any(f.rule == "rate-limit-no-persistent-store/no-persistent-store" for f in findings)


def test_rate_limit_no_persistent_store_redis_uri_silences(tmp_path: Path) -> None:
    (tmp_path / "limiter.py").write_text(
        "from slowapi import Limiter\nfrom slowapi.util import get_remote_address\n"
        "limiter = Limiter(key_func=get_remote_address, storage_uri='redis://localhost:6379')\n",
        encoding="utf-8",
    )
    assert RateLimitNoPersistentStoreGuard().run(tmp_path, _python_nodirs_prof(tmp_path)) == []


def test_rate_limit_no_persistent_store_memcached_uri_silences(tmp_path: Path) -> None:
    (tmp_path / "limiter.py").write_text(
        "from limits import storage\nfrom slowapi import Limiter\nfrom slowapi.util import get_remote_address\n"
        "limiter = Limiter(key_func=get_remote_address, storage_uri='memcached://localhost:11211')\n",
        encoding="utf-8",
    )
    assert RateLimitNoPersistentStoreGuard().run(tmp_path, _python_nodirs_prof(tmp_path)) == []


def test_rate_limit_no_persistent_store_non_literal_uri_silent(tmp_path: Path) -> None:
    # A settings/env-var indirection: can't tell what it resolves to, so no false positive.
    (tmp_path / "limiter.py").write_text(
        "from slowapi import Limiter\nfrom slowapi.util import get_remote_address\n"
        "import os\n"
        "limiter = Limiter(key_func=get_remote_address, storage_uri=os.environ['RATE_LIMIT_STORAGE_URI'])\n",
        encoding="utf-8",
    )
    assert RateLimitNoPersistentStoreGuard().run(tmp_path, _python_nodirs_prof(tmp_path)) == []


def test_rate_limit_no_persistent_store_no_slowapi_silent(tmp_path: Path) -> None:
    (tmp_path / "main.py").write_text("from fastapi import FastAPI\napp = FastAPI()\n", encoding="utf-8")
    assert RateLimitNoPersistentStoreGuard().run(tmp_path, _python_nodirs_prof(tmp_path)) == []


def test_rate_limit_no_persistent_store_pragma_silences(tmp_path: Path) -> None:
    (tmp_path / "limiter.py").write_text(
        "# security: allow-in-memory-rate-limit\n"
        "from slowapi import Limiter\nfrom slowapi.util import get_remote_address\n"
        "limiter = Limiter(key_func=get_remote_address)\n",
        encoding="utf-8",
    )
    assert RateLimitNoPersistentStoreGuard().run(tmp_path, _python_nodirs_prof(tmp_path)) == []


def test_rate_limit_no_persistent_store_multiline_limiter_fires(tmp_path: Path) -> None:
    (tmp_path / "limiter.py").write_text(
        "from slowapi import Limiter\n"
        "from slowapi.util import get_remote_address\n"
        "limiter = Limiter(\n"
        "    key_func=get_remote_address,\n"
        ")\n",
        encoding="utf-8",
    )
    findings = RateLimitNoPersistentStoreGuard().run(tmp_path, _python_nodirs_prof(tmp_path))
    assert any(f.rule == "rate-limit-no-persistent-store/no-persistent-store" for f in findings)
    assert findings[0].location.endswith("limiter.py:3")


def test_rate_limit_no_persistent_store_multiline_redis_uri_silent(tmp_path: Path) -> None:
    # FP-bait: a multi-line Limiter( with a persisted storage_uri= on a continuation
    # line must not fire.
    (tmp_path / "limiter.py").write_text(
        "from slowapi import Limiter\n"
        "from slowapi.util import get_remote_address\n"
        "limiter = Limiter(\n"
        "    key_func=get_remote_address,\n"
        "    storage_uri='redis://localhost:6379',\n"
        ")\n",
        encoding="utf-8",
    )
    assert RateLimitNoPersistentStoreGuard().run(tmp_path, _python_nodirs_prof(tmp_path)) == []


def test_rate_limit_no_persistent_store_multi_file_cross_file_scoping(tmp_path: Path) -> None:
    # Round-2 fix (PR #732 review, High): a persistent-store Limiter() in ONE file must not
    # silence a genuinely in-memory Limiter() in a DIFFERENT file — the earlier aggregate-
    # project-wide design let exactly this happen. Two files, one persistent one not: exactly
    # one finding, pointing at the in-memory one.
    (tmp_path / "webhooks.py").write_text(
        "from slowapi import Limiter\n"
        "from slowapi.util import get_remote_address\n"
        "webhook_limiter = Limiter(key_func=get_remote_address, storage_uri='redis://localhost:6379')\n",
        encoding="utf-8",
    )
    (tmp_path / "auth.py").write_text(
        "from slowapi import Limiter\n"
        "from slowapi.util import get_remote_address\n"
        "auth_limiter = Limiter(key_func=get_remote_address)\n",
        encoding="utf-8",
    )
    findings = RateLimitNoPersistentStoreGuard().run(tmp_path, _python_nodirs_prof(tmp_path))
    matches = [f for f in findings if f.rule == "rate-limit-no-persistent-store/no-persistent-store"]
    assert len(matches) == 1
    assert matches[0].location.endswith("auth.py:3")


def test_rate_limit_no_persistent_store_commented_storage_uri_not_counted(tmp_path: Path) -> None:
    # A storage_uri= that exists ONLY in a comment must not count as configured: the
    # joined call text is comment-stripped, so this Limiter has no storage_uri at all
    # and the guard still fires.
    (tmp_path / "limiter.py").write_text(
        "from slowapi import Limiter\n"
        "from slowapi.util import get_remote_address\n"
        "limiter = Limiter(\n"
        "    key_func=get_remote_address,\n"
        "    # storage_uri='redis://localhost:6379',\n"
        ")\n",
        encoding="utf-8",
    )
    findings = RateLimitNoPersistentStoreGuard().run(tmp_path, _python_nodirs_prof(tmp_path))
    assert any(f.rule == "rate-limit-no-persistent-store/no-persistent-store" for f in findings)


def test_rate_limit_no_persistent_store_ratelimiter_dependency_not_flagged(tmp_path: Path) -> None:
    # FP-bait (PR #732 round-2 review, Medium): fastapi-limiter's per-route `RateLimiter(...)`
    # dependency ends in "Limiter" but is NOT a slowapi `Limiter()` and takes no `storage_uri=`.
    # slowapi is imported here (so pass 1 finds the library in use and the guard proceeds), but
    # the only constructor call is `RateLimiter(` — the word-anchored `_LIMITER_INIT` must not
    # match it, so nothing fires. This test FAILS on the old substring regex `Limiter\s*\(`.
    (tmp_path / "routes.py").write_text(
        "from slowapi import Limiter\n"
        "from fastapi import Depends, FastAPI\n"
        "from fastapi_limiter.depends import RateLimiter\n"
        "app = FastAPI()\n"
        "\n"
        "@app.get('/items', dependencies=[Depends(RateLimiter(times=5, seconds=60))])\n"
        "def items() -> dict[str, int]:\n"
        "    return {'ok': 1}\n",
        encoding="utf-8",
    )
    assert RateLimitNoPersistentStoreGuard().run(tmp_path, _python_nodirs_prof(tmp_path)) == []


def test_rate_limit_no_persistent_store_commented_limiter_not_counted(tmp_path: Path) -> None:
    # FP-bait (#897): a `Limiter(` inside a `#` comment above the real call is NOT a second
    # instantiation. The issue's own repro: exactly ONE finding, on the real line. The raw-line
    # match reported this one Limiter twice (limiter.py:3 and :4).
    (tmp_path / "limiter.py").write_text(
        "from slowapi import Limiter\n"
        "from slowapi.util import get_remote_address\n"
        "# Mirrors the editor's existing Limiter(key_func=get_remote_address) pattern.\n"
        "limiter = Limiter(key_func=get_remote_address)   # <- the real finding\n",
        encoding="utf-8",
    )
    findings = RateLimitNoPersistentStoreGuard().run(tmp_path, _python_nodirs_prof(tmp_path))
    matches = [f for f in findings if f.rule == "rate-limit-no-persistent-store/no-persistent-store"]
    assert len(matches) == 1
    assert matches[0].location.endswith("limiter.py:4")


def test_rate_limit_no_persistent_store_comment_only_mention_silent(tmp_path: Path) -> None:
    # FP-bait (#897): the library is imported and the ONLY `Limiter(` is in a comment — there is
    # no instantiation at all, so nothing fires (the raw-line match produced a finding on line 2).
    (tmp_path / "limiter.py").write_text(
        "from slowapi import Limiter\n"
        "# TODO: add Limiter(key_func=get_remote_address) here once the Redis backend is provisioned\n",
        encoding="utf-8",
    )
    assert RateLimitNoPersistentStoreGuard().run(tmp_path, _python_nodirs_prof(tmp_path)) == []


def test_rate_limit_no_persistent_store_trailing_comment_mention_not_counted(tmp_path: Path) -> None:
    # FP-bait (#897): a trailing `# ... Limiter( ...` comment on an UNRELATED line is not an
    # instantiation either — exactly one finding, on the real call (line 3), none on line 4.
    (tmp_path / "limiter.py").write_text(
        "from slowapi import Limiter\n"
        "from slowapi.util import get_remote_address\n"
        "limiter = Limiter(key_func=get_remote_address)\n"
        "DEFAULT_LIMIT = '5/minute'  # applied by the Limiter( above\n",
        encoding="utf-8",
    )
    findings = RateLimitNoPersistentStoreGuard().run(tmp_path, _python_nodirs_prof(tmp_path))
    matches = [f for f in findings if f.rule == "rate-limit-no-persistent-store/no-persistent-store"]
    assert len(matches) == 1
    assert matches[0].location.endswith("limiter.py:3")


def test_rate_limit_no_persistent_store_real_limiter_with_trailing_comment_still_fires(tmp_path: Path) -> None:
    # Rule 1 — the direction #897's narrowing traded against: a REAL in-memory `Limiter(...)` that
    # carries a trailing comment must still fire, at its own line. Two shapes:
    #   a.py — the comment names a persistent `storage_uri='redis://...'` that is NOT configured.
    #          On the raw line this comment was read as the call's own argument and SILENCED the
    #          finding (a false negative the raw-line read caused); stripped first, it still fires.
    #   b.py — the comment holds an unbalanced `(`. The paren-balance check runs on the stripped
    #          line, so it must not start a bogus multi-line join that swallows the call.
    (tmp_path / "a.py").write_text(
        "from slowapi import Limiter\n"
        "from slowapi.util import get_remote_address\n"
        "limiter = Limiter(key_func=get_remote_address)  # later: storage_uri='redis://cache:6379'\n",
        encoding="utf-8",
    )
    (tmp_path / "b.py").write_text(
        "from slowapi import Limiter\n"
        "from slowapi.util import get_remote_address\n"
        "limiter = Limiter(key_func=get_remote_address)  # TODO: pick a backend (see limits docs\n"
        "app_name = 'svc'\n",
        encoding="utf-8",
    )
    findings = RateLimitNoPersistentStoreGuard().run(tmp_path, _python_nodirs_prof(tmp_path))
    locations = sorted(
        f.location for f in findings if f.rule == "rate-limit-no-persistent-store/no-persistent-store"
    )
    assert len(locations) == 2
    assert locations[0].endswith("a.py:3")
    assert locations[1].endswith("b.py:3")
