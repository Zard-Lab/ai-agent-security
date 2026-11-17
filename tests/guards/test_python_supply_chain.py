from __future__ import annotations

from agentsec.guards.python_supply_chain import PythonSupplyChainGuard
from tests.guards._common import *  # noqa: F401,F403


def test_pysc_flags_requirements_without_hashed_lock(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("fastapi==0.115.0\n", encoding="utf-8")
    findings = PythonSupplyChainGuard().run(tmp_path, _pyprof(tmp_path))
    hits = [f for f in findings if f.rule == "python-supply-chain/no-locked-hashes"]
    assert len(hits) == 1 and hits[0].severity == "high"

def test_pysc_passes_with_uv_lock_and_cooldown(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "x"\nversion = "0"\ndependencies = ["fastapi==0.1"]\n'
        '[tool.uv]\nexclude-newer = "48 hours"\n', encoding="utf-8"
    )
    (tmp_path / "uv.lock").write_text(
        'version = 1\n[[package]]\nname = "fastapi"\nversion = "0.1"\n'
        '[[package.wheels]]\nhash = "sha256:deadbeef"\n', encoding="utf-8"
    )
    rules = _rules(PythonSupplyChainGuard().run(tmp_path, _pyprof(tmp_path)))
    assert "python-supply-chain/no-locked-hashes" not in rules
    assert "python-supply-chain/no-cooldown" not in rules
    assert "python-supply-chain/unpinned" not in rules

def test_pysc_flags_missing_cooldown(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "x"\nversion = "0"\ndependencies = ["fastapi==0.1"]\n', encoding="utf-8"
    )
    (tmp_path / "uv.lock").write_text('version = 1\n[[package]]\nname = "fastapi"\n', encoding="utf-8")
    rules = _rules(PythonSupplyChainGuard().run(tmp_path, _pyprof(tmp_path)))
    assert "python-supply-chain/no-cooldown" in rules
    assert "python-supply-chain/no-locked-hashes" not in rules

def test_pysc_cooldown_too_short_and_ok(tmp_path: Path) -> None:
    (tmp_path / "uv.lock").write_text("version = 1\n", encoding="utf-8")
    pp = tmp_path / "pyproject.toml"
    base = '[project]\nname = "x"\nversion = "0"\ndependencies = ["fastapi==0.1"]\n'
    pp.write_text(base + '[tool.uv]\nexclude-newer = "24 hours"\n', encoding="utf-8")
    short = [f for f in PythonSupplyChainGuard().run(tmp_path, _pyprof(tmp_path))
             if f.rule == "python-supply-chain/cooldown-too-short"]
    assert len(short) == 1 and short[0].severity == "low"
    pp.write_text(base + '[tool.uv]\nexclude-newer = "2 days"\n', encoding="utf-8")
    assert "python-supply-chain/cooldown-too-short" not in _rules(
        PythonSupplyChainGuard().run(tmp_path, _pyprof(tmp_path))
    )

def test_pysc_cooldown_pragma_opt_out(tmp_path: Path) -> None:
    (tmp_path / "uv.lock").write_text("version = 1\n", encoding="utf-8")
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "x"\nversion = "0"\ndependencies = ["fastapi==0.1"]\n'
        "# security: allow-no-cooldown\n", encoding="utf-8"
    )
    assert "python-supply-chain/no-cooldown" not in _rules(
        PythonSupplyChainGuard().run(tmp_path, _pyprof(tmp_path))
    )

def test_pysc_flags_unpinned_and_extra_index(tmp_path: Path) -> None:
    # no hashed lock -> the loose `requests>=2` is the install set; a non-benign extra index fires too.
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "x"\nversion = "0"\ndependencies = ["requests>=2"]\n'
        '[tool.uv]\nexclude-newer = "48 hours"\nextra-index-url = "https://evil/simple"\n', encoding="utf-8"
    )
    rules = _rules(PythonSupplyChainGuard().run(tmp_path, _pyprof(tmp_path)))
    assert "python-supply-chain/unpinned" in rules
    assert "python-supply-chain/extra-index-url" in rules

def test_pysc_hashed_lock_makes_pyproject_abstract(tmp_path: Path) -> None:
    # T2c precision: a hashed lock (uv.lock, or requirements-locked.txt with --hash=) pins the
    # resolved tree, so the abstract pyproject's loose specifiers are NOT unpinned.
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "x"\nversion = "0"\ndependencies = ["requests>=2", "fastapi"]\n'
        '[tool.uv]\nexclude-newer = "48 hours"\n', encoding="utf-8"
    )
    (tmp_path / "requirements-locked.txt").write_text(
        "requests==2.32.3 \\\n    --hash=sha256:aaa\nfastapi==0.111.0 \\\n    --hash=sha256:bbb\n", encoding="utf-8"
    )
    assert "python-supply-chain/unpinned" not in _rules(
        PythonSupplyChainGuard().run(tmp_path, _pyprof(tmp_path))
    )

def test_pysc_benign_pytorch_index_silent(tmp_path: Path) -> None:
    # T2c precision: the PyTorch CPU wheel index is a trusted vendor host, not dependency confusion.
    (tmp_path / "requirements.txt").write_text(
        "torch==2.3.0\n--extra-index-url https://download.pytorch.org/whl/cpu\n", encoding="utf-8"
    )
    assert "python-supply-chain/extra-index-url" not in _rules(
        PythonSupplyChainGuard().run(tmp_path, _pyprof(tmp_path))
    )

def test_pysc_nonbenign_extra_index_still_fires(tmp_path: Path) -> None:
    # ...but any OTHER extra index is still a dependency-confusion risk and must fire (no FN).
    (tmp_path / "requirements.txt").write_text(
        "internal-pkg==1.0\n--extra-index-url https://pypi.mycorp.example/simple\n", encoding="utf-8"
    )
    assert "python-supply-chain/extra-index-url" in _rules(
        PythonSupplyChainGuard().run(tmp_path, _pyprof(tmp_path))
    )

def test_pysc_flags_insecure_http_index(tmp_path: Path) -> None:
    (tmp_path / "uv.lock").write_text("version = 1\n", encoding="utf-8")
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "x"\nversion = "0"\ndependencies = ["fastapi==0.1"]\n'
        '[tool.uv]\nexclude-newer = "48 hours"\nindex-url = "http://internal/simple"\n', encoding="utf-8"
    )
    hits = [f for f in PythonSupplyChainGuard().run(tmp_path, _pyprof(tmp_path))
            if f.rule == "python-supply-chain/insecure-index"]
    assert len(hits) == 1 and hits[0].severity == "high"

def test_pysc_exception_db_no_expiry_and_lapsed(tmp_path: Path) -> None:
    (tmp_path / "pip-audit-exceptions.json").write_text(
        '{"exceptions": ['
        '{"id": "CVE-1", "package": "a"},'
        '{"id": "CVE-2", "package": "b", "review_by": "2000-01-01"},'
        '{"id": "CVE-3", "package": "c", "review_by": "2999-01-01"}'
        "]}", encoding="utf-8"
    )
    prof = _pyprof(tmp_path)
    prof.today = date(2026, 1, 1)  # explicit audit date — never read off the wall clock
    rules = _rules(PythonSupplyChainGuard().run(tmp_path, prof))
    assert "python-supply-chain/exception-no-expiry" in rules
    assert "python-supply-chain/exception-lapsed" in rules
    # Determinism (M2): without an explicit date, lapse is NOT evaluated (no date.today()),
    # so the lapsed finding does not appear — the guard is a pure function of bytes + profile.
    rules_nodate = _rules(PythonSupplyChainGuard().run(tmp_path, _pyprof(tmp_path)))
    assert "python-supply-chain/exception-no-expiry" in rules_nodate
    assert "python-supply-chain/exception-lapsed" not in rules_nodate

def test_pysc_exception_db_malformed_no_crash(tmp_path: Path) -> None:
    (tmp_path / "pip-audit-exceptions.json").write_text("{not valid json", encoding="utf-8")
    # must not raise; exception checks simply produce nothing
    rules = _rules(PythonSupplyChainGuard().run(tmp_path, _pyprof(tmp_path)))
    assert not any(r.startswith("python-supply-chain/exception") for r in rules)

def test_pysc_utf16_requirements_pins_not_flagged_unpinned(tmp_path: Path) -> None:
    # UTF-16 (BOM) requirements with pinned deps: must decode correctly so the
    # pins are seen (no false 'unpinned'); still HIGH no-locked-hashes (no hashes).
    (tmp_path / "requirements.txt").write_bytes("fastapi==0.1\nrequests==2.0\n".encode("utf-16"))
    rules = _rules(PythonSupplyChainGuard().run(tmp_path, _pyprof(tmp_path)))
    assert "python-supply-chain/unpinned" not in rules
    assert "python-supply-chain/no-locked-hashes" in rules

def test_pysc_na_for_non_python() -> None:
    prof = mkprofile(Path("/tmp"), features={"frontend"})
    assert PythonSupplyChainGuard().applies(prof) is False

def test_pysc_skips_monorepo_sub_package_pyproject(tmp_path: Path) -> None:
    # A pyproject.toml with [build-system] in a subdirectory is a publishable library
    # sub-package — its users manage the lockfile; the guard must stay silent.
    from agentsec.guards.python_supply_chain import dependency_dirs
    sub = tmp_path / "libs" / "mylib"
    sub.mkdir(parents=True)
    (sub / "pyproject.toml").write_text(
        "[build-system]\nrequires = ['hatchling']\nbuild-backend = 'hatchling.build'\n"
        "[project]\nname = 'mylib'\ndependencies = ['fastapi>=0.100']\n",
        encoding="utf-8",
    )
    dirs = dependency_dirs(tmp_path, _pyprof(tmp_path))
    assert sub not in dirs

def test_pysc_keeps_root_pyproject_even_with_build_system(tmp_path: Path) -> None:
    # The repo ROOT pyproject.toml is always scanned even if it has [build-system].
    from agentsec.guards.python_supply_chain import dependency_dirs
    (tmp_path / "pyproject.toml").write_text(
        "[build-system]\nrequires = ['hatchling']\nbuild-backend = 'hatchling.build'\n"
        "[project]\nname = 'myapp'\ndependencies = ['fastapi']\n",
        encoding="utf-8",
    )
    dirs = dependency_dirs(tmp_path, _pyprof(tmp_path))
    assert tmp_path in dirs

def test_pysc_skips_requirements_in_nonprod_path(tmp_path: Path) -> None:
    # requirements.txt inside examples/ is tutorial scaffolding — skip it.
    from agentsec.guards.python_supply_chain import dependency_dirs
    ex = tmp_path / "examples" / "basic"
    ex.mkdir(parents=True)
    (ex / "requirements.txt").write_text("flask\n", encoding="utf-8")
    dirs = dependency_dirs(tmp_path, _pyprof(tmp_path))
    assert ex not in dirs



def test_pysc_commented_extra_index_url_not_flagged(tmp_path: Path) -> None:
    # FP-bait (#424): a commented `# --extra-index-url http://...` in a requirements file must
    # not be counted as a real insecure index.
    (tmp_path / "requirements.txt").write_text(
        "fastapi==0.1\n# --extra-index-url http://evil.example/simple\n", encoding="utf-8"
    )
    rules = _rules(PythonSupplyChainGuard().run(tmp_path, _pyprof(tmp_path)))
    assert "python-supply-chain/extra-index-url" not in rules
    assert "python-supply-chain/insecure-index" not in rules


def test_pysc_commented_uv_exclude_newer_still_flags_no_cooldown(tmp_path: Path) -> None:
    # FN fix (#424): a commented-out `# UV_EXCLUDE_NEWER=...` in .env must NOT be counted as a
    # configured cooldown, so the no-cooldown finding still fires.
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "x"\nversion = "0"\ndependencies = ["fastapi==0.1"]\n', encoding="utf-8"
    )
    (tmp_path / "uv.lock").write_text('version = 1\n[[package]]\nname = "fastapi"\n', encoding="utf-8")
    (tmp_path / ".env").write_text("# UV_EXCLUDE_NEWER=48h\n", encoding="utf-8")
    rules = _rules(PythonSupplyChainGuard().run(tmp_path, _pyprof(tmp_path)))
    assert "python-supply-chain/no-cooldown" in rules


def test_pysc_extra_index_url_still_fires_with_trailing_comment(tmp_path: Path) -> None:
    # #441 review (Low): a real --extra-index-url with a TRAILING comment must still fire.
    (tmp_path / "requirements.txt").write_text(
        "fastapi==0.1\n--extra-index-url http://mirror.example/simple  # legacy mirror\n", encoding="utf-8"
    )
    rules = _rules(PythonSupplyChainGuard().run(tmp_path, _pyprof(tmp_path)))
    assert "python-supply-chain/extra-index-url" in rules
    assert "python-supply-chain/insecure-index" in rules


def test_pysc_uv_exclude_newer_still_suppresses_with_trailing_comment(tmp_path: Path) -> None:
    # #441 review (Low): a real UV_EXCLUDE_NEWER with a TRAILING comment must still suppress
    # no-cooldown (the value survives the comment strip).
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "x"\nversion = "0"\ndependencies = ["fastapi==0.1"]\n', encoding="utf-8"
    )
    (tmp_path / "uv.lock").write_text('version = 1\n[[package]]\nname = "fastapi"\n', encoding="utf-8")
    (tmp_path / ".env").write_text("UV_EXCLUDE_NEWER=48h  # release-age cooldown\n", encoding="utf-8")
    rules = _rules(PythonSupplyChainGuard().run(tmp_path, _pyprof(tmp_path)))
    assert "python-supply-chain/no-cooldown" not in rules


# --------------------------------------------------------------------------- #424 E6 (#1000)
_E6_PYPROJECT = '[project]\nname = "x"\nversion = "0"\ndependencies = ["fastapi==0.1"]\n'
_E6_UV_LOCK = 'version = 1\n[[package]]\nname = "fastapi"\n'
_E6_PYPROJECT_EXTRA_INDEX = (
    '[project]\nname = "x"\nversion = "0"\ndependencies = ["requests>=2"]\n'
    '[tool.uv]\nexclude-newer = "48 hours"\nextra-index-url = "https://evil/simple"\n'
)
_E6_EXTRA_INDEX_RULES = {
    "python-supply-chain/extra-index-url",
    "python-supply-chain/no-locked-hashes",
    "python-supply-chain/unpinned",
}


def _e6_with_description(pyproject: str, text: str) -> str:
    """`pyproject` with a `[project]` description string carrying `text` (a TOML string literal)."""
    return pyproject.replace('version = "0"\n', f'version = "0"\ndescription = "{text}"\n', 1)


def test_python_supply_chain_pragma_quoted_in_a_string_does_not_suppress_cooldown_pyproject(
    tmp_path: Path,
) -> None:
    # #424 E6 (#1000): the pyproject cooldown opt-out reads the hash comment view, so a TOML string
    # quoting the pragma is content. Only a real `#` comment (`test_pysc_cooldown_pragma_opt_out`) opts out.
    (tmp_path / "pyproject.toml").write_text(
        _e6_with_description(_E6_PYPROJECT, "opt out with # security: allow-no-cooldown"), encoding="utf-8"
    )
    (tmp_path / "uv.lock").write_text(_E6_UV_LOCK, encoding="utf-8")
    rules = _rules(PythonSupplyChainGuard().run(tmp_path, _pyprof(tmp_path)))
    assert rules == {"python-supply-chain/no-cooldown"}


def test_python_supply_chain_pragma_quoted_in_a_string_does_not_suppress_cooldown_uv_toml(
    tmp_path: Path,
) -> None:
    # #424 E6 (#1000): the uv.toml cooldown opt-out reads the hash comment view, so a TOML string
    # quoting the pragma is content. Only a real `#` comment (`..._pragma_comment_suppresses_uv_toml`) opts out.
    (tmp_path / "pyproject.toml").write_text(_E6_PYPROJECT, encoding="utf-8")
    (tmp_path / "uv.lock").write_text(_E6_UV_LOCK, encoding="utf-8")
    (tmp_path / "uv.toml").write_text('note = "opt out with # security: allow-no-cooldown"\n', encoding="utf-8")
    rules = _rules(PythonSupplyChainGuard().run(tmp_path, _pyprof(tmp_path)))
    assert rules == {"python-supply-chain/no-cooldown"}


def test_python_supply_chain_pragma_quoted_in_a_string_does_not_suppress_cooldown_env(
    tmp_path: Path,
) -> None:
    # #424 E6 (#1000): the .env cooldown opt-out reads the hash comment view, so a quoted value
    # carrying the pragma is content. Only a real `#` comment (`..._pragma_comment_suppresses_env`) opts out.
    (tmp_path / "pyproject.toml").write_text(_E6_PYPROJECT, encoding="utf-8")
    (tmp_path / "uv.lock").write_text(_E6_UV_LOCK, encoding="utf-8")
    (tmp_path / ".env").write_text('HELP="opt out with # security: allow-no-cooldown"\n', encoding="utf-8")
    rules = _rules(PythonSupplyChainGuard().run(tmp_path, _pyprof(tmp_path)))
    assert rules == {"python-supply-chain/no-cooldown"}


def test_python_supply_chain_pragma_quoted_in_a_string_does_not_suppress_extra_index_pyproject(
    tmp_path: Path,
) -> None:
    # #424 E6 (#1000): the pyproject extra-index opt-out reads the hash comment view, so a TOML string
    # quoting the pragma is content. Only a real `#` comment (`..._extra_index_pyproject` below) opts out.
    (tmp_path / "pyproject.toml").write_text(
        _e6_with_description(_E6_PYPROJECT_EXTRA_INDEX, "opt out with # security: allow-extra-index"),
        encoding="utf-8",
    )
    rules = _rules(PythonSupplyChainGuard().run(tmp_path, _pyprof(tmp_path)))
    assert rules == _E6_EXTRA_INDEX_RULES


def test_python_supply_chain_pragma_comment_suppresses_uv_toml(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text(_E6_PYPROJECT, encoding="utf-8")
    (tmp_path / "uv.lock").write_text(_E6_UV_LOCK, encoding="utf-8")
    (tmp_path / "uv.toml").write_text('cache-dir = ".uv-cache"\n', encoding="utf-8")
    assert _rules(PythonSupplyChainGuard().run(tmp_path, _pyprof(tmp_path))) == {
        "python-supply-chain/no-cooldown"
    }
    (tmp_path / "uv.toml").write_text(
        '# security: allow-no-cooldown\ncache-dir = ".uv-cache"\n', encoding="utf-8"
    )
    assert PythonSupplyChainGuard().run(tmp_path, _pyprof(tmp_path)) == []


def test_python_supply_chain_pragma_comment_suppresses_env(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text(_E6_PYPROJECT, encoding="utf-8")
    (tmp_path / "uv.lock").write_text(_E6_UV_LOCK, encoding="utf-8")
    (tmp_path / ".env").write_text("DEBUG=0\n", encoding="utf-8")
    assert _rules(PythonSupplyChainGuard().run(tmp_path, _pyprof(tmp_path))) == {
        "python-supply-chain/no-cooldown"
    }
    (tmp_path / ".env").write_text("# security: allow-no-cooldown\nDEBUG=0\n", encoding="utf-8")
    assert PythonSupplyChainGuard().run(tmp_path, _pyprof(tmp_path)) == []


def test_python_supply_chain_pragma_comment_suppresses_extra_index_pyproject(tmp_path: Path) -> None:
    pp = tmp_path / "pyproject.toml"
    pp.write_text(_E6_PYPROJECT_EXTRA_INDEX, encoding="utf-8")
    assert _rules(PythonSupplyChainGuard().run(tmp_path, _pyprof(tmp_path))) == _E6_EXTRA_INDEX_RULES
    pp.write_text(_E6_PYPROJECT_EXTRA_INDEX + "# security: allow-extra-index\n", encoding="utf-8")
    assert _rules(PythonSupplyChainGuard().run(tmp_path, _pyprof(tmp_path))) == (
        _E6_EXTRA_INDEX_RULES - {"python-supply-chain/extra-index-url"}
    )


def test_python_supply_chain_pragma_comment_suppresses_extra_index_requirements(tmp_path: Path) -> None:
    req = tmp_path / "requirements.txt"
    body = "internal-pkg==1.0\n--extra-index-url https://pypi.mycorp.example/simple\n"
    req.write_text(body, encoding="utf-8")
    assert _rules(PythonSupplyChainGuard().run(tmp_path, _pyprof(tmp_path))) == {
        "python-supply-chain/extra-index-url",
        "python-supply-chain/no-cooldown",
        "python-supply-chain/no-locked-hashes",
    }
    req.write_text(body + "# security: allow-extra-index\n", encoding="utf-8")
    assert _rules(PythonSupplyChainGuard().run(tmp_path, _pyprof(tmp_path))) == {
        "python-supply-chain/no-cooldown",
        "python-supply-chain/no-locked-hashes",
    }
