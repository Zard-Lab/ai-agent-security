from __future__ import annotations

from agentsec.guards.redis_glob_pattern_injection import RedisGlobInjectionGuard
from tests.guards._common import *  # noqa: F401,F403


def _prof(tmp_path: Path):
    return mkprofile(tmp_path, features={"python", "redis"}, python_dirs=["."])


def test_redis_glob_pattern_injection_scan_iter_match_fstring_fires(tmp_path: Path) -> None:
    (tmp_path / "health_api.py").write_text(
        "def get_group_health(redis_client, group_name):\n"
        "    keys = redis_client.scan_iter(match=f'health:{group_name}:*')\n"
        "    return [redis_client.get(k) for k in keys]\n",
        encoding="utf-8",
    )
    findings = RedisGlobInjectionGuard().run(tmp_path, _prof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "redis-glob-pattern-injection/unescaped-glob-pattern"
    assert findings[0].severity == "high"


def test_redis_glob_pattern_injection_keys_fstring_fires(tmp_path: Path) -> None:
    (tmp_path / "health_api.py").write_text(
        "def get_group_health(redis_client, group_name):\n"
        "    return redis_client.keys(f'health:{group_name}:*')\n",
        encoding="utf-8",
    )
    findings = RedisGlobInjectionGuard().run(tmp_path, _prof(tmp_path))
    assert len(findings) == 1


def test_redis_glob_pattern_injection_scan_positional_match_fires(tmp_path: Path) -> None:
    (tmp_path / "health_api.py").write_text(
        "def get_group_health(redis_client, group_name, cursor=0):\n"
        "    return redis_client.scan(cursor, 'health:' + group_name + ':*')\n",
        encoding="utf-8",
    )
    findings = RedisGlobInjectionGuard().run(tmp_path, _prof(tmp_path))
    assert len(findings) == 1


def test_redis_glob_pattern_injection_delete_torrent_hash_shape_fires(tmp_path: Path) -> None:
    # The destructive variant named in the CVE: a crafted infohash with glob metacharacters
    # matching keys belonging to a DIFFERENT torrent than the one requested.
    (tmp_path / "torrents.py").write_text(
        "def delete_manual_torrent(redis_client, infohash):\n"
        "    for key in redis_client.scan_iter(match=f'torrent:{infohash}:*'):\n"
        "        redis_client.delete(key)\n",
        encoding="utf-8",
    )
    findings = RedisGlobInjectionGuard().run(tmp_path, _prof(tmp_path))
    assert len(findings) == 1


def test_redis_glob_pattern_injection_static_literal_stays_silent(tmp_path: Path) -> None:
    (tmp_path / "health_api.py").write_text(
        "def get_all_health(redis_client):\n"
        "    return redis_client.scan_iter(match='health:*')\n",
        encoding="utf-8",
    )
    assert RedisGlobInjectionGuard().run(tmp_path, _prof(tmp_path)) == []


def test_redis_glob_pattern_injection_keys_no_args_stays_silent(tmp_path: Path) -> None:
    # FP-bait: `.keys()` with no pattern argument at all (matches everything, but no injection).
    (tmp_path / "health_api.py").write_text(
        "def get_all_keys(redis_client):\n"
        "    return redis_client.keys()\n",
        encoding="utf-8",
    )
    assert RedisGlobInjectionGuard().run(tmp_path, _prof(tmp_path)) == []


def test_redis_glob_pattern_injection_unrelated_get_call_stays_silent(tmp_path: Path) -> None:
    # FP-bait: an f-string used to build a plain GET key (not a glob pattern at all).
    (tmp_path / "health_api.py").write_text(
        "def get_health(redis_client, group_name):\n"
        "    return redis_client.get(f'health:{group_name}')\n",
        encoding="utf-8",
    )
    assert RedisGlobInjectionGuard().run(tmp_path, _prof(tmp_path)) == []


def test_redis_glob_pattern_injection_pragma_opt_out(tmp_path: Path) -> None:
    (tmp_path / "health_api.py").write_text(
        "# security: allow-redis-glob-concat\n"
        "def get_group_health(redis_client, group_name):\n"
        "    return redis_client.keys(f'health:{group_name}:*')\n",
        encoding="utf-8",
    )
    assert RedisGlobInjectionGuard().run(tmp_path, _prof(tmp_path)) == []


def test_redis_glob_pattern_injection_not_applicable_without_redis(tmp_path: Path) -> None:
    prof = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    assert RedisGlobInjectionGuard().applies(prof) is False


def test_redis_glob_pattern_injection_applies_with_redis_feature() -> None:
    prof = mkprofile(Path("/tmp"), features={"python", "redis"})
    assert RedisGlobInjectionGuard().applies(prof) is True
