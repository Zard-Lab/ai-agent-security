from __future__ import annotations

from agentsec.guards.bulk_env_var_harvesting import BulkEnvVarHarvestingGuard
from tests.guards._common import *  # noqa: F401,F403


def test_bulk_env_var_harvesting_flags_environ_items(tmp_path: Path) -> None:
    (tmp_path / "steal.py").write_text(
        "for name, value in os.environ.items():\n"
        "    send_to_remote(name, value)\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    findings = BulkEnvVarHarvestingGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "bulk-env-var-harvesting/environment-enumeration"
    assert findings[0].severity == "high"

def test_bulk_env_var_harvesting_silent_environ_copy(tmp_path: Path) -> None:
    # Regression: a bare os.environ.copy()/dict(os.environ) is deliberately NOT
    # flagged -- it's a common, benign idiom for safely reading a few named keys
    # (found as a false positive in this project's own net.py during self-audit).
    (tmp_path / "safe.py").write_text(
        "all_vars = os.environ.copy()\n"
        'db_url = all_vars.get("DATABASE_URL")\n',
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    assert BulkEnvVarHarvestingGuard().run(tmp_path, profile) == []

def test_bulk_env_var_harvesting_silent_dict_environ(tmp_path: Path) -> None:
    (tmp_path / "safe.py").write_text(
        "all_vars = dict(os.environ)\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    assert BulkEnvVarHarvestingGuard().run(tmp_path, profile) == []

def test_bulk_env_var_harvesting_flags_js_object_keys(tmp_path: Path) -> None:
    (tmp_path / "steal.js").write_text(
        "const names = Object.keys(process.env);\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    findings = BulkEnvVarHarvestingGuard().run(tmp_path, profile)
    assert len(findings) == 1

def test_bulk_env_var_harvesting_silent_env_kwarg_form(tmp_path: Path) -> None:
    # This exact shape is mcp-tool-env-inheritance's own finding, not this guard's --
    # confirms no double-fire on the subprocess env= passthrough shape.
    (tmp_path / "server.py").write_text(
        "subprocess.run(cmd, env=os.environ.copy())\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    assert BulkEnvVarHarvestingGuard().run(tmp_path, profile) == []

def test_bulk_env_var_harvesting_silent_named_variable(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        'db_url = os.environ["DATABASE_URL"]\n',
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    assert BulkEnvVarHarvestingGuard().run(tmp_path, profile) == []

def test_bulk_env_var_harvesting_pragma_silences(tmp_path: Path) -> None:
    content = (
        "# security: allow-bulk-env-harvesting\n"
        "for name, value in os.environ.items():\n"
        "    pass\n"
    )
    (tmp_path / "diagnostics.py").write_text(content, encoding="utf-8")
    profile = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    assert BulkEnvVarHarvestingGuard().run(tmp_path, profile) == []

def test_bulk_env_var_harvesting_silent_filtered_comprehension(tmp_path: Path) -> None:
    # Regression (PR #393 review #3): a comprehension that filters os.environ.items() by a
    # key prefix reads a bounded, namespaced SUBSET -- a benign, common config idiom -- and
    # must NOT fire HIGH the way an unfiltered full-environment harvest does.
    (tmp_path / "config.py").write_text(
        "cfg = {k: v for k, v in os.environ.items() if k.startswith('MYAPP_')}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    assert BulkEnvVarHarvestingGuard().run(tmp_path, profile) == []

def test_bulk_env_var_harvesting_flags_single_line_statement_harvest(tmp_path: Path) -> None:
    # Regression (PR #393 final-pass review): the filtered-comprehension carve-out must NOT catch a
    # `for`-loop STATEMENT written on one line. `for k, v in os.environ.items(): send(v if v else '')`
    # enumerates the whole environment (the trailing ternary is a value null-check, not a key
    # filter) -- it is a genuine harvest and must still fire HIGH.
    (tmp_path / "steal.py").write_text(
        "for k, v in os.environ.items(): exfiltrate(v if v else '')\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    findings = BulkEnvVarHarvestingGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].severity == "high"

def test_bulk_env_var_harvesting_flags_unfiltered_comprehension(tmp_path: Path) -> None:
    # The carve-out is narrow: an UNfiltered comprehension is still a full-environment
    # enumeration and still fires.
    (tmp_path / "dump.py").write_text(
        "cfg = {k: v for k, v in os.environ.items()}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    assert len(BulkEnvVarHarvestingGuard().run(tmp_path, profile)) == 1

def test_bulk_env_var_harvesting_covers_js_only_repo(tmp_path: Path) -> None:
    # Regression (PR #393 review #1): the guard is universal, so its JS detection fires on a
    # repo with no `python` feature -- a language-feature gate silently missed this.
    (tmp_path / "steal.js").write_text(
        "const names = Object.keys(process.env);\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"javascript"})
    assert BulkEnvVarHarvestingGuard().applies(profile) is True
    assert len(BulkEnvVarHarvestingGuard().run(tmp_path, profile)) == 1

def test_bulk_env_var_harvesting_skips_nonproduct_path(tmp_path: Path) -> None:
    # Regression (PR #393 review #2): a target repo's own test/fixture files are skipped, so a
    # test that legitimately iterates os.environ.items() does not false-fire.
    tests_dir = tmp_path / "tests"
    tests_dir.mkdir()
    (tests_dir / "steal.py").write_text(
        "for name, value in os.environ.items():\n    print(name)\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    assert BulkEnvVarHarvestingGuard().run(tmp_path, profile) == []

def test_bulk_env_var_harvesting_applies_universally() -> None:
    # Universal guard: env-harvesting code can appear in any stack (see applies() rationale).
    assert BulkEnvVarHarvestingGuard().applies(mkprofile(Path("/tmp"), features={"java"})) is True
    assert BulkEnvVarHarvestingGuard().applies(mkprofile(Path("/tmp"), features=set())) is True
