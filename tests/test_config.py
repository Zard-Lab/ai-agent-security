"""Tests for the per-repo `.agentsec/config.json` loader and the opt-in archive-path
suppression it drives (config -> profile.archive_segments -> is_nonproduct_path -> guards)."""
from __future__ import annotations

import os
from pathlib import Path

import pytest

from agentsec.audit import audit
from agentsec.config import _DEFAULT_NONPRODUCT_PATHS, RepoConfig, load_repo_config, write_repo_config
from agentsec.detect import ARCHIVE_SEGMENTS
from agentsec.guards.base import is_nonproduct_path
from agentsec.prioritize import reachability


def _write_config(root: Path, body: str) -> None:
    cfg = root / ".agentsec"
    cfg.mkdir(parents=True, exist_ok=True)
    (cfg / "config.json").write_text(body, encoding="utf-8")


# --- loader: total / never raises, opt-in defaults ---

def test_missing_config_is_empty(tmp_path: Path) -> None:
    assert load_repo_config(tmp_path) == RepoConfig()
    assert load_repo_config(tmp_path).archive_segments == frozenset()


def test_true_expands_to_default_set(tmp_path: Path) -> None:
    _write_config(tmp_path, '{"archive_paths": true}')
    assert load_repo_config(tmp_path).archive_segments == ARCHIVE_SEGMENTS


def test_list_is_normalized(tmp_path: Path) -> None:
    _write_config(tmp_path, '{"archive_paths": ["Old", "vendor_old/", "  ", 7]}')
    assert load_repo_config(tmp_path).archive_segments == frozenset({"old", "vendor_old"})


def test_malformed_json_is_empty(tmp_path: Path) -> None:
    _write_config(tmp_path, "not json {{{")
    assert load_repo_config(tmp_path).archive_segments == frozenset()


@pytest.mark.parametrize(
    "raw",
    [
        b'{"archive_paths": ["caf\xe9"]}',                 # latin-1: any non-UTF-8 byte
        '{"archive_paths": true}'.encode("utf-16"),        # Notepad "Unicode" / PS 5.1 Out-File
    ],
    ids=["latin-1", "utf-16"],
)
def test_non_utf8_config_is_empty(tmp_path: Path, raw: bytes) -> None:
    # Regression (#513): `UnicodeDecodeError` is a ValueError, not an OSError, so it escaped the
    # read's `except OSError` and tracebacked every audit-path verb despite "Never raises".
    cfg = tmp_path / ".agentsec" / "config.json"
    cfg.parent.mkdir()
    cfg.write_bytes(raw)
    with pytest.raises(UnicodeDecodeError):  # the bytes really are un-decodable
        cfg.read_text(encoding="utf-8-sig")
    assert load_repo_config(tmp_path) == RepoConfig()


@pytest.mark.parametrize(
    ("raw", "why"),
    [
        ('{"network": {"tier": 1}}'.encode("utf-16"), "not UTF-8 text"),
        (b'{"network": {"tier": 1}, oops', "not valid JSON"),
        (b'["old"]', "not a JSON object"),
    ],
    ids=["utf-16", "malformed", "non-object"],
)
def test_unusable_config_warns_once_per_path(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], raw: bytes, why: str
) -> None:
    # #961 round-1 M1: falling back to defaults without a word is a failure that presents as
    # success, since the user's archive_paths / network.tier silently stop applying. The loader runs
    # 2-4 times per `audit` (network-tier resolution, `audit()`, the advisor), so it warns once per path.
    cfg = tmp_path / ".agentsec" / "config.json"
    cfg.parent.mkdir()
    cfg.write_bytes(raw)
    assert load_repo_config(tmp_path) == RepoConfig()
    assert load_repo_config(tmp_path) == RepoConfig()
    err = capsys.readouterr().err
    assert err.count("warning: ignoring") == 1
    assert why in err


def test_a_different_unusable_shape_at_the_same_path_warns_again(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # #961 round-2 L1: the dedup keyed on the path alone, so a config that broke a second, different
    # way in the same process was never reported. Repeats of the same reason still warn once.
    cfg = tmp_path / ".agentsec" / "config.json"
    cfg.parent.mkdir()
    cfg.write_bytes('{"network": {"tier": 1}}'.encode("utf-16"))
    load_repo_config(tmp_path)
    load_repo_config(tmp_path)
    cfg.write_bytes(b'{"network": {"tier": 1}, oops')
    load_repo_config(tmp_path)
    load_repo_config(tmp_path)
    err = capsys.readouterr().err
    assert err.count("warning: ignoring") == 2
    assert "not UTF-8 text" in err
    assert "not valid JSON" in err


@pytest.mark.parametrize(
    "raw",
    [None, b"", b"  \n", b"{}", b'{"archive_paths": ["old"]}', b'\xef\xbb\xbf{"network": {"tier": 1}}'],
    ids=["absent", "empty", "blank", "empty-object", "valid", "bom-valid"],
)
def test_absent_or_usable_config_stays_silent(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], raw: bytes | None
) -> None:
    # The traded-against direction of the M1 warning: an absent, blank (`touch`ed) or valid config
    # is the normal case and must never print it. A blank file is what `write_repo_config` already
    # treats as a fresh start.
    if raw is not None:
        cfg = tmp_path / ".agentsec" / "config.json"
        cfg.parent.mkdir()
        cfg.write_bytes(raw)
    load_repo_config(tmp_path)
    assert capsys.readouterr().err == ""


def test_utf8_bom_config_is_honored(tmp_path: Path) -> None:
    # A BOM'd config (Notepad "UTF-8 with BOM") used to fail `json.loads` and be silently ignored —
    # the user's archive_paths / network.tier quietly did nothing (#513).
    cfg = tmp_path / ".agentsec" / "config.json"
    cfg.parent.mkdir()
    cfg.write_bytes(b'\xef\xbb\xbf{"archive_paths": ["old"], "network": {"tier": 1}}')
    loaded = load_repo_config(tmp_path)
    assert loaded.archive_segments == frozenset({"old"})
    assert loaded.network_tier == 1


def test_non_dict_top_level_is_empty(tmp_path: Path) -> None:
    _write_config(tmp_path, '["old"]')
    assert load_repo_config(tmp_path).archive_segments == frozenset()


def test_unexpected_value_type_is_empty(tmp_path: Path) -> None:
    _write_config(tmp_path, '{"archive_paths": 42}')
    assert load_repo_config(tmp_path).archive_segments == frozenset()


# --- is_nonproduct_path: archives are opt-in, never default ---

def test_archive_not_skipped_by_default() -> None:
    assert is_nonproduct_path("old/agent.py") is False
    assert is_nonproduct_path("legacy/routes.py") is False


def test_archive_skipped_when_opted_in() -> None:
    seg = frozenset({"old", "legacy"})
    assert is_nonproduct_path("old/agent.py", seg) is True
    assert is_nonproduct_path("LEGACY/routes.py", seg) is True  # case-insensitive
    assert is_nonproduct_path("backend/agent.py", seg) is False
    assert is_nonproduct_path("old", seg) is False  # a file named "old" is not an old/ tree


def test_test_paths_always_skipped_regardless_of_opt_in() -> None:
    assert is_nonproduct_path("tests/test_x.py") is True
    assert is_nonproduct_path("src/Foo.test.tsx") is True


def test_alembic_is_default_nonproduct() -> None:
    # Scoped §C Phase 1 — `alembic/` migration plumbing is the one addition that is UNIVERSALLY
    # non-product (no guard targets it as an attack surface), so it belongs in the shared default
    # list (round-2 §A.2). Confirmed universal by the canary + efficacy suites.
    assert is_nonproduct_path("alembic/env.py") is True
    assert is_nonproduct_path("app/backend/alembic/versions/abc.py") is True
    assert is_nonproduct_path("app/main.py") is False


def test_guard_relative_surfaces_are_NOT_in_the_shared_list() -> None:
    # Lesson (canary + efficacy caught this): "non-product" is guard-RELATIVE. `.claude/` and
    # `.env.example` are the ATTACK SURFACE for ai-instruction-poisoning / claude-code-compromise —
    # they must NOT be in the shared `is_nonproduct_path` gate (a guard that wants to skip them does so
    # in its own run()). `*.example` / `*.dev.yml` likewise stay per-guard.
    assert is_nonproduct_path(".claude/settings.json") is False
    assert is_nonproduct_path("app/.claude/skills/x.md") is False
    assert is_nonproduct_path(".env.example") is False
    assert is_nonproduct_path("Dockerfile.user.example") is False
    assert is_nonproduct_path("docker-compose.dev.yml") is False
    assert is_nonproduct_path("src/claude.py") is False  # a file named claude is not the .claude/ dir


# --- end-to-end: a guard finding in an archive tree is suppressed only when opted in ---

def test_audit_suppresses_archive_tree_only_when_opted_in(tmp_path: Path) -> None:
    # token_in_localstorage fires on a live credential write; plant one in old/.
    (tmp_path / "package.json").write_text(
        '{"dependencies": {"react": "^18.0.0", "vite": "^5.0.0"}}', encoding="utf-8"
    )
    old = tmp_path / "old"
    old.mkdir()
    (old / "auth.ts").write_text(
        'localStorage.setItem("access_token", session.access_token)\n', encoding="utf-8"
    )

    def has_old_finding() -> bool:
        result = audit(tmp_path, run_scanners=False, exceptions_path=Path(os.devnull))
        return any("old/" in (f.location or "").replace("\\", "/") for f in result.findings)

    # Default: nothing opted in -> the old/ finding is scanned and surfaced.
    assert has_old_finding() is True

    # Opt in -> guards skip the old/ tree.
    _write_config(tmp_path, '{"archive_paths": ["old"]}')
    assert has_old_finding() is False


def test_audit_archive_opt_in_covers_llm_foundation_guards(tmp_path: Path) -> None:
    # The #133 LLM guards must honor the archive opt-in too (threaded via the follow-on).
    # agent-tool-audit-log fires on an unlogged @agent.tool; plant one in old/.
    (tmp_path / "requirements.txt").write_text("pydantic-ai\n", encoding="utf-8")
    old = tmp_path / "old"
    old.mkdir()
    (old / "agent.py").write_text(
        "from pydantic_ai import Agent\n"
        "agent = Agent('openai:gpt-4o')\n"
        "@agent.tool\n"
        "def my_tool(ctx) -> str:\n"
        "    return ctx.deps.do_work()\n",
        encoding="utf-8",
    )

    def has_tool_finding() -> bool:
        result = audit(tmp_path, run_scanners=False, exceptions_path=Path(os.devnull))
        return any(f.check_id == "agent-tool-audit-log" for f in result.findings)

    assert has_tool_finding() is True  # surfaced by default
    _write_config(tmp_path, '{"archive_paths": ["old"]}')
    assert has_tool_finding() is False  # suppressed once opted in


# --- archive_paths fully excludes the tree (whole-file guards too), with disclosure ---

def _cors_repo(tmp_path: Path) -> str:
    body = (
        "from fastapi.middleware.cors import CORSMiddleware\n"
        'app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True)\n'
    )
    (tmp_path / "main.py").write_text("from fastapi import FastAPI\napp=FastAPI()\n", encoding="utf-8")
    (tmp_path / "app.py").write_text(body, encoding="utf-8")  # product
    old = tmp_path / "old"
    old.mkdir()
    (old / "app.py").write_text(body, encoding="utf-8")  # archived
    return body


def _cors_locs(tmp_path: Path) -> list[str]:
    result = audit(tmp_path, run_scanners=False, exceptions_path=Path(os.devnull))
    return sorted(f.location.split(":")[0] for f in result.findings if f.check_id == "cors-wildcard")


def test_archive_paths_excludes_whole_file_guard(tmp_path: Path) -> None:
    # cors-wildcard does NOT consult is_nonproduct_path (it's a whole-file guard), so only the
    # new universal archive-exclude pass can drop its old/ finding. This is the flagship gap.
    _cors_repo(tmp_path)
    assert _cors_locs(tmp_path) == ["app.py", "old/app.py"]  # both by default
    _write_config(tmp_path, '{"archive_paths": ["old"]}')
    assert _cors_locs(tmp_path) == ["app.py"]  # archived one dropped, product kept

    result = audit(tmp_path, run_scanners=False, exceptions_path=Path(os.devnull))
    archived = [f for f in result.archive_excluded if f.check_id == "cors-wildcard"]
    assert archived and all("old/" in f.location for f in archived)


def test_archive_paths_default_does_not_exclude(tmp_path: Path) -> None:
    _cors_repo(tmp_path)
    result = audit(tmp_path, run_scanners=False, exceptions_path=Path(os.devnull))
    assert result.archive_excluded == []  # nothing dropped without opt-in
    assert "old/app.py" in [f.location.split(":")[0] for f in result.findings]  # still surfaced (demoted, not dropped)


def test_archive_exclusion_disclosed(tmp_path: Path, capsys) -> None:  # type: ignore[no-untyped-def]
    from agentsec.cli import main

    _cors_repo(tmp_path)
    _write_config(tmp_path, '{"archive_paths": ["old"]}')
    main(["audit", str(tmp_path), "--guards-only", "--no-fail"])
    out = capsys.readouterr().out
    assert "Excluded as archived (.agentsec/config.json: old):" in out


# --- nonproduct_paths tier: loader (DEMOTE, never drop) ---

def test_nonproduct_paths_loads_list(tmp_path: Path) -> None:
    _write_config(tmp_path, '{"nonproduct_paths": ["Evals", "scripts/"]}')
    cfg = load_repo_config(tmp_path)
    assert cfg.nonproduct_segments == frozenset({"evals", "scripts"})
    assert cfg.archive_segments == frozenset()  # independent tier


def test_nonproduct_paths_true_expands_to_default(tmp_path: Path) -> None:
    _write_config(tmp_path, '{"nonproduct_paths": true}')
    assert load_repo_config(tmp_path).nonproduct_segments == _DEFAULT_NONPRODUCT_PATHS


def test_nonproduct_paths_default_empty(tmp_path: Path) -> None:
    assert load_repo_config(tmp_path).nonproduct_segments == frozenset()


# --- write_repo_config: merge-safe, preserves unknown keys, never clobbers ---

def test_write_repo_config_creates_and_merges(tmp_path: Path) -> None:
    # pre-existing file with an unknown key + an archive list
    _write_config(tmp_path, '{"archive_paths": ["old"], "custom_key": 42}')
    changed = write_repo_config(tmp_path, archive_add=("legacy",), nonproduct_add=("evals", "Scripts/"))
    assert changed == {"archive_paths": ["legacy", "old"], "nonproduct_paths": ["evals", "scripts"]}
    cfg = load_repo_config(tmp_path)
    assert cfg.archive_segments == frozenset({"old", "legacy"})        # unioned, not clobbered
    assert cfg.nonproduct_segments == frozenset({"evals", "scripts"})  # normalized
    import json
    raw = json.loads((tmp_path / ".agentsec" / "config.json").read_text(encoding="utf-8"))
    assert raw["custom_key"] == 42  # unknown key preserved


def test_write_repo_config_no_file_yet(tmp_path: Path) -> None:
    changed = write_repo_config(tmp_path, nonproduct_add=("evals",))
    assert changed == {"nonproduct_paths": ["evals"]}
    assert (tmp_path / ".agentsec" / "config.json").is_file()
    assert load_repo_config(tmp_path).nonproduct_segments == frozenset({"evals"})


def test_write_repo_config_idempotent(tmp_path: Path) -> None:
    write_repo_config(tmp_path, nonproduct_add=("evals",))
    write_repo_config(tmp_path, nonproduct_add=("evals",))  # same add again
    assert load_repo_config(tmp_path).nonproduct_segments == frozenset({"evals"})


def test_write_repo_config_expands_true_before_union(tmp_path: Path) -> None:
    _write_config(tmp_path, '{"nonproduct_paths": true}')
    write_repo_config(tmp_path, nonproduct_add=("my_seed_dir",))
    seg = load_repo_config(tmp_path).nonproduct_segments
    assert "my_seed_dir" in seg and seg >= _DEFAULT_NONPRODUCT_PATHS  # true expanded, then unioned


# --- end-to-end: nonproduct_paths DEMOTES (stamps + reachability low) but never drops ---

def test_nonproduct_paths_demotes_but_keeps_finding(tmp_path: Path) -> None:
    _cors_repo(tmp_path)  # plants a cors-wildcard finding in old/app.py (a whole-file guard)
    _write_config(tmp_path, '{"nonproduct_paths": ["old"]}')
    result = audit(tmp_path, run_scanners=False, exceptions_path=Path(os.devnull))
    assert result.archive_excluded == []  # demote tier never drops
    old_cors = [f for f in result.findings if f.check_id == "cors-wildcard" and "old/" in f.location]
    assert old_cors, "the old/ finding must still be present (demoted, not dropped)"
    assert all(f.nonproduct and reachability(f) == "low" for f in old_cors)
    # the product finding is untouched
    prod = [f for f in result.findings if f.check_id == "cors-wildcard" and f.location.startswith("app.py")]
    assert prod and all(not f.nonproduct for f in prod)
