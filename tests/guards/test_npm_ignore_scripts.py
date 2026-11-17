from __future__ import annotations

from agentsec.guards.npm_ignore_scripts import NpmIgnoreScriptsGuard
from tests.guards._common import *  # noqa: F401,F403


def _ci_locations(tmp_path: Path, run_line: str, *, filename: str = "ci.yml") -> list[str]:
    """Locations of every finding for a repo whose only variable is one `- run:` line.

    `.npmrc` is hardened, so the repo-level finding never fires and the returned list is
    exactly the CI-line signal under test — the #533 measurements were made this way.

    Separators are posix-normalized. `guards/base.py::rel()` returns an OS-NATIVE relative
    path, so on Windows the guard emits `.github\\workflows\\ci.yml:4`; a guard-level test
    calls `run()` directly and so bypasses `audit.py`'s `normalize_location()`, which is what
    posix-normalizes the location on the real report/SARIF/baseline path. Normalizing here
    keeps the assertions readable as one exact POSIX literal instead of branching per platform
    (same move as `test_mcp_config_security.py`'s `.replace("\\", "/")`).
    """
    (tmp_path / "package.json").write_text('{"name": "app"}', encoding="utf-8")
    (tmp_path / ".npmrc").write_text("ignore-scripts=true\n", encoding="utf-8")
    wf_dir = tmp_path / ".github" / "workflows"
    wf_dir.mkdir(parents=True, exist_ok=True)
    (wf_dir / filename).write_text(
        f"jobs:\n  build:\n    steps:\n      - run: {run_line}\n", encoding="utf-8"
    )
    profile = mkprofile(tmp_path, features={"frontend"})
    return [f.location.replace("\\", "/") for f in NpmIgnoreScriptsGuard().run(tmp_path, profile)]


def test_npm_ignore_scripts_no_npmrc_fires(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text('{"name": "app"}', encoding="utf-8")
    profile = mkprofile(tmp_path, features={"frontend"})
    findings = NpmIgnoreScriptsGuard().run(tmp_path, profile)
    assert len(findings) >= 1
    assert findings[0].rule == "npm-ignore-scripts/missing-ignore-scripts"
    assert findings[0].severity == "high"

def test_npm_ignore_scripts_npmrc_without_flag_fires(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text('{"name": "app"}', encoding="utf-8")
    (tmp_path / ".npmrc").write_text("registry=https://registry.npmjs.org\n", encoding="utf-8")
    profile = mkprofile(tmp_path, features={"javascript"})
    findings = NpmIgnoreScriptsGuard().run(tmp_path, profile)
    assert len(findings) >= 1
    assert findings[0].rule == "npm-ignore-scripts/missing-ignore-scripts"

def test_npm_ignore_scripts_silent_when_flag_set(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text('{"name": "app"}', encoding="utf-8")
    (tmp_path / ".npmrc").write_text("ignore-scripts=true\n", encoding="utf-8")
    profile = mkprofile(tmp_path, features={"frontend"})
    findings = NpmIgnoreScriptsGuard().run(tmp_path, profile)
    assert findings == []

def test_npm_ignore_scripts_pragma_silences_npmrc(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text('{"name": "app"}', encoding="utf-8")
    (tmp_path / ".npmrc").write_text(
        "registry=https://registry.npmjs.org\n# security: allow-npm-scripts\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"frontend"})
    findings = NpmIgnoreScriptsGuard().run(tmp_path, profile)
    assert findings == []

def test_npm_ignore_scripts_ci_workflow_fires(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text('{"name": "app"}', encoding="utf-8")
    (tmp_path / ".npmrc").write_text("ignore-scripts=true\n", encoding="utf-8")
    wf_dir = tmp_path / ".github" / "workflows"
    wf_dir.mkdir(parents=True)
    (wf_dir / "ci.yml").write_text(
        "jobs:\n  build:\n    steps:\n      - run: npm install\n", encoding="utf-8"
    )
    profile = mkprofile(tmp_path, features={"frontend"})
    findings = NpmIgnoreScriptsGuard().run(tmp_path, profile)
    assert len(findings) >= 1
    assert any(f.rule == "npm-ignore-scripts/missing-ignore-scripts" for f in findings)

def test_npm_ignore_scripts_ci_workflow_with_flag_silent(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text('{"name": "app"}', encoding="utf-8")
    (tmp_path / ".npmrc").write_text("ignore-scripts=true\n", encoding="utf-8")
    wf_dir = tmp_path / ".github" / "workflows"
    wf_dir.mkdir(parents=True)
    (wf_dir / "ci.yml").write_text(
        "jobs:\n  build:\n    steps:\n      - run: npm ci --ignore-scripts\n", encoding="utf-8"
    )
    profile = mkprofile(tmp_path, features={"frontend"})
    findings = NpmIgnoreScriptsGuard().run(tmp_path, profile)
    assert findings == []

def test_npm_ignore_scripts_pragma_silences_ci(tmp_path: Path) -> None:
    # The opt-out the CI remediation prints: the pragma on the install's own line (#539). This
    # used to plant it on line 1 and the install on line 5, which pinned FILE scope.
    assert _ci_locations(tmp_path, "npm install  # security: allow-npm-scripts") == []

def test_npm_ignore_scripts_no_package_json_silent(tmp_path: Path) -> None:
    (tmp_path / ".npmrc").write_text("registry=https://registry.npmjs.org\n", encoding="utf-8")
    profile = mkprofile(tmp_path, features={"frontend"})
    findings = NpmIgnoreScriptsGuard().run(tmp_path, profile)
    assert findings == []

def test_npm_ignore_scripts_silent_with_spaced_form(tmp_path: Path) -> None:
    # #423 FP-bait: npm trims whitespace around `=`, so `ignore-scripts = true` is a valid
    # hardened .npmrc — must not fire.
    (tmp_path / "package.json").write_text('{"name": "x"}\n', encoding="utf-8")
    (tmp_path / ".npmrc").write_text("ignore-scripts = true\n", encoding="utf-8")
    profile = mkprofile(tmp_path, features={"javascript"}, python_dirs=["."])
    assert [
        f for f in NpmIgnoreScriptsGuard().run(tmp_path, profile)
        if f.rule == "npm-ignore-scripts/missing-ignore-scripts" and f.location.endswith(".npmrc")
    ] == []

def test_npm_ignore_scripts_applies_gate(tmp_path: Path) -> None:
    profile = mkprofile(tmp_path, features={"python", "fastapi"})
    assert NpmIgnoreScriptsGuard().applies(profile) is False

# --- #533: the exemption lookahead must not read past the command it exempts ---

def test_npm_ignore_scripts_ci_trailing_comment_fires(tmp_path: Path) -> None:
    # #533, the reported bug: a comment merely MENTIONING the flag is not the flag. The
    # install is genuinely unprotected, so the line must still fire.
    assert _ci_locations(tmp_path, "npm install  # TODO: use --ignore-scripts later") == [
        ".github/workflows/ci.yml:4"
    ]

def test_npm_ignore_scripts_ci_shell_separator_shapes_fire(tmp_path: Path) -> None:
    # #533, the general class the comment is one instance of: a `--ignore-scripts` belonging
    # to a LATER command on the line never protected the earlier install. `&&` is the
    # realistic shape (a protected second install does not retroactively protect the first).
    for line in (
        "npm install && npm ci --ignore-scripts",
        "npm install ; echo --ignore-scripts",
        "npm install | tee --ignore-scripts.log",
    ):
        assert _ci_locations(tmp_path, line) == [".github/workflows/ci.yml:4"], line

def test_npm_ignore_scripts_ci_protected_stays_silent(tmp_path: Path) -> None:
    # FP bait for the narrowing above: a flag actually passed to the command still exempts
    # it, including when an unrelated comment follows and in the `=true` spelling.
    for line in (
        "npm install --ignore-scripts",
        "npm ci --ignore-scripts  # pinned lockfile",
        "npm install --ignore-scripts=true",
    ):
        assert _ci_locations(tmp_path, line) == [], line

def test_npm_ignore_scripts_ci_git_ref_fragment_stays_silent(tmp_path: Path) -> None:
    # LOAD-BEARING FP bait (#533). `#` is npm's git-ref and URL-fragment separator, not only a
    # comment marker, so a `#` glued to a non-space character must NOT end the exemption span.
    # This goes red if the pattern is ever simplified to `[^\n#]` (the fix proposed in the
    # issue, measured 8/14) or to claude_code_compromise.py's `[^\n;|&#]` (11/14).
    for line in (
        "npm install git+https://github.com/o/r.git#v1.2.3 --ignore-scripts",
        "npm install github:owner/repo#semver:^1.0 --ignore-scripts",
        "npm install --registry https://r.example/#mirror --ignore-scripts",
    ):
        assert _ci_locations(tmp_path, line) == [], line
    # …and the same git-ref install WITHOUT the flag is still unprotected, so the exemption
    # was narrowed rather than the whole shape excused.
    assert _ci_locations(tmp_path, "npm install git+https://github.com/o/r.git#v1.2.3") == [
        ".github/workflows/ci.yml:4"
    ]

def test_npm_ignore_scripts_ci_hash_before_the_command_stays_silent(tmp_path: Path) -> None:
    # FP bait: a `#` inside an earlier quoted string precedes the match start, so it never
    # entered the lookahead span — the protected install stays silent.
    assert _ci_locations(tmp_path, 'echo "issue #42" && npm install --ignore-scripts') == []

def test_npm_ignore_scripts_ci_quoted_separator_stays_silent(tmp_path: Path) -> None:
    # FP bait (#540 review, H1): `;`, `|` and `&` are separators only OUTSIDE quotes. A registry
    # URL is quoted precisely BECAUSE it contains `&` — treating that as a hard stop reported a
    # protected install as HIGH. Each line below passes the flag to the command it protects.
    for line in (
        'npm install --registry "https://r.example/?token=X&scope=@org" --ignore-scripts',
        "npm install --foo 'a;b' --ignore-scripts",
        'npm install --foo "a|b" --ignore-scripts',
        'npm install --foo "it\'s fine" --ignore-scripts',
    ):
        assert _ci_locations(tmp_path, line) == [], line

def test_npm_ignore_scripts_ci_quoted_flag_stays_silent(tmp_path: Path) -> None:
    # FP bait: quoting the flag itself does not stop it being passed. This is what the one narrow
    # way into a quoted span buys, and it goes red if that alternative is ever dropped.
    for line in ('npm install "--ignore-scripts"', "npm install '--ignore-scripts'"):
        assert _ci_locations(tmp_path, line) == [], line

def test_npm_ignore_scripts_ci_quoted_flag_of_later_command_fires(tmp_path: Path) -> None:
    # The mandatory other direction: making a quoted flag visible must NOT become a new bypass.
    # Here the flag belongs to `echo`, so the install is unprotected and must still fire.
    assert _ci_locations(tmp_path, 'npm install && echo "--ignore-scripts"') == [
        ".github/workflows/ci.yml:4"
    ]

def test_npm_ignore_scripts_ci_unquoted_separator_still_fires(tmp_path: Path) -> None:
    # An UNQUOTED `&` genuinely backgrounds the command, so `--ignore-scripts` belongs to a
    # different command and this install really is unprotected. Firing is correct, and this
    # pins that the quote handling did not become a blanket "ignore all separators".
    assert _ci_locations(
        tmp_path, "npm install --registry https://r.example/?a=1&b=2 --ignore-scripts"
    ) == [".github/workflows/ci.yml:4"]

def test_npm_ignore_scripts_yaml_extension_workflow_fires(tmp_path: Path) -> None:
    # #533 (a): the `.yaml` spelling is a real workflow extension. Scanning only `.yml` made
    # this guard the sole workflow scanner in the codebase missing it — actions-sha-pin and
    # ci-secret-env-unscoped both already pass `(".yml", ".yaml")`.
    assert _ci_locations(tmp_path, "npm install", filename="ci.yaml") == [
        ".github/workflows/ci.yaml:4"
    ]

def test_npm_ignore_scripts_yaml_extension_protected_stays_silent(tmp_path: Path) -> None:
    # FP bait for the widened extension set: new file coverage must not arrive with new FPs.
    for line in (
        "npm ci --ignore-scripts",
        "npm install git+https://github.com/o/r.git#v1.2.3 --ignore-scripts",
    ):
        assert _ci_locations(tmp_path, line, filename="ci.yaml") == [], line

def test_npm_ignore_scripts_yaml_outside_workflows_not_scanned(tmp_path: Path) -> None:
    # Scope bait: the walk is rooted at `.github/workflows`, so widening the extension set
    # must not start scanning every `.yaml` in the repo.
    (tmp_path / "package.json").write_text('{"name": "app"}', encoding="utf-8")
    (tmp_path / ".npmrc").write_text("ignore-scripts=true\n", encoding="utf-8")
    (tmp_path / "docker-compose.yaml").write_text(
        "services:\n  web:\n    command: npm install\n", encoding="utf-8"
    )
    profile = mkprofile(tmp_path, features={"frontend"})
    assert NpmIgnoreScriptsGuard().run(tmp_path, profile) == []


# --- NPM_CONFIG_IGNORE_SCRIPTS environment-variable form ---

def test_npm_ignore_scripts_env_file_truthy_silences_repo_finding(tmp_path: Path) -> None:
    # The false negative this closes: previously the env-var form was an accepted, undetected
    # omission — a repo protected ONLY via .env still reported "missing .npmrc". No .npmrc at
    # all here, so the pre-fix guard would have fired.
    (tmp_path / "package.json").write_text('{"name": "app"}', encoding="utf-8")
    (tmp_path / ".env").write_text("NPM_CONFIG_IGNORE_SCRIPTS=true\n", encoding="utf-8")
    profile = mkprofile(tmp_path, features={"frontend"})
    findings = NpmIgnoreScriptsGuard().run(tmp_path, profile)
    assert findings == []

def test_npm_ignore_scripts_env_file_dotenv_variant_silences(tmp_path: Path) -> None:
    # `.env.production` etc — the `.env.*` glob, matching the convention other guards use.
    (tmp_path / "package.json").write_text('{"name": "app"}', encoding="utf-8")
    (tmp_path / ".env.production").write_text(
        "NPM_CONFIG_IGNORE_SCRIPTS=1\n", encoding="utf-8"
    )
    profile = mkprofile(tmp_path, features={"frontend"})
    assert NpmIgnoreScriptsGuard().run(tmp_path, profile) == []

def test_npm_ignore_scripts_compose_environment_block_silences(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text('{"name": "app"}', encoding="utf-8")
    (tmp_path / "docker-compose.yml").write_text(
        "services:\n"
        "  web:\n"
        "    build: .\n"
        "    environment:\n"
        '      NPM_CONFIG_IGNORE_SCRIPTS: "true"\n',
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"frontend"})
    assert NpmIgnoreScriptsGuard().run(tmp_path, profile) == []

def test_npm_ignore_scripts_compose_environment_list_form_silences(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text('{"name": "app"}', encoding="utf-8")
    (tmp_path / "docker-compose.yaml").write_text(
        "services:\n"
        "  web:\n"
        "    environment:\n"
        "      - NPM_CONFIG_IGNORE_SCRIPTS=true\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"frontend"})
    assert NpmIgnoreScriptsGuard().run(tmp_path, profile) == []

def test_npm_ignore_scripts_env_var_falsy_still_fires(tmp_path: Path) -> None:
    # FP-bait / traded-against direction: a FALSY value (or the var merely mentioned) must not
    # be treated as protection — the install is genuinely unprotected here.
    (tmp_path / "package.json").write_text('{"name": "app"}', encoding="utf-8")
    (tmp_path / ".env").write_text("NPM_CONFIG_IGNORE_SCRIPTS=false\n", encoding="utf-8")
    profile = mkprofile(tmp_path, features={"frontend"})
    findings = NpmIgnoreScriptsGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "npm-ignore-scripts/missing-ignore-scripts"

def test_npm_ignore_scripts_env_var_absent_still_fires(tmp_path: Path) -> None:
    # Baseline vulnerable case: no .npmrc, no .env, no compose file — must still fire (the
    # env-var check must never manufacture protection that isn't there).
    (tmp_path / "package.json").write_text('{"name": "app"}', encoding="utf-8")
    profile = mkprofile(tmp_path, features={"frontend"})
    findings = NpmIgnoreScriptsGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "npm-ignore-scripts/missing-ignore-scripts"

def test_npm_ignore_scripts_env_var_commented_out_in_dotenv_still_fires(tmp_path: Path) -> None:
    # #685 fix-commit round, High 2: a .env line that only MENTIONS the var inside a `#`
    # comment ("# NPM_CONFIG_IGNORE_SCRIPTS=true once we roll this out") must not be read as
    # real protection -- reopens the exact #533 bug class already fixed for the sibling
    # CI-line regex, on this newer env-var regex instead.
    (tmp_path / "package.json").write_text('{"name": "app"}', encoding="utf-8")
    (tmp_path / ".env").write_text(
        "# NPM_CONFIG_IGNORE_SCRIPTS=true once we roll this out\n", encoding="utf-8"
    )
    profile = mkprofile(tmp_path, features={"frontend"})
    findings = NpmIgnoreScriptsGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "npm-ignore-scripts/missing-ignore-scripts"


def test_npm_ignore_scripts_env_var_real_assignment_with_trailing_comment_still_silences(
    tmp_path: Path,
) -> None:
    # Still silences the OTHER direction: a real assignment followed by an unrelated trailing
    # comment must not be broken by the comment-stripping fix.
    (tmp_path / "package.json").write_text('{"name": "app"}', encoding="utf-8")
    (tmp_path / ".env").write_text(
        "NPM_CONFIG_IGNORE_SCRIPTS=true  # rolled out repo-wide\n", encoding="utf-8"
    )
    profile = mkprofile(tmp_path, features={"frontend"})
    assert NpmIgnoreScriptsGuard().run(tmp_path, profile) == []


def test_npm_ignore_scripts_ci_env_commented_out_still_fires(tmp_path: Path) -> None:
    # Same #685 fix, CI-workflow call site: a commented-out env-var mention must not silence
    # a genuinely unprotected npm install in the same workflow file.
    assert _ci_locations(
        tmp_path, "# NPM_CONFIG_IGNORE_SCRIPTS=true\n          npm install"
    ) == [".github/workflows/ci.yml:5"]


def test_npm_ignore_scripts_ci_env_block_silences_ci_line(tmp_path: Path) -> None:
    # The CI-side env-var form: a workflow-level `env:` block protects every npm install/ci
    # line in that same workflow file. `.npmrc` is hardened so only the CI signal is under test.
    (tmp_path / "package.json").write_text('{"name": "app"}', encoding="utf-8")
    (tmp_path / ".npmrc").write_text("ignore-scripts=true\n", encoding="utf-8")
    wf_dir = tmp_path / ".github" / "workflows"
    wf_dir.mkdir(parents=True)
    (wf_dir / "ci.yml").write_text(
        "env:\n"
        "  NPM_CONFIG_IGNORE_SCRIPTS: true\n"
        "jobs:\n"
        "  build:\n"
        "    steps:\n"
        "      - run: npm install\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"frontend"})
    assert NpmIgnoreScriptsGuard().run(tmp_path, profile) == []

def test_npm_ignore_scripts_ci_inline_env_assignment_silences_ci_line(tmp_path: Path) -> None:
    # An inline shell assignment on the run line itself is also recognized.
    assert _ci_locations(
        tmp_path, "NPM_CONFIG_IGNORE_SCRIPTS=true npm install"
    ) == []

def test_npm_ignore_scripts_ci_env_block_missing_still_fires(tmp_path: Path) -> None:
    # Traded-against direction: a workflow with no env-var protection at all must still fire
    # its CI-line finding exactly as before this change.
    assert _ci_locations(tmp_path, "npm install") == [".github/workflows/ci.yml:4"]

def test_npm_ignore_scripts_env_var_in_unrelated_file_not_scanned(tmp_path: Path) -> None:
    # Scope bait: NPM_CONFIG_IGNORE_SCRIPTS mentioned in some other file (not .env, not
    # docker-compose, not a CI workflow) must not silence the repo-level finding.
    (tmp_path / "package.json").write_text('{"name": "app"}', encoding="utf-8")
    (tmp_path / "README.md").write_text(
        "Set NPM_CONFIG_IGNORE_SCRIPTS=true in your shell.\n", encoding="utf-8"
    )
    profile = mkprofile(tmp_path, features={"frontend"})
    findings = NpmIgnoreScriptsGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "npm-ignore-scripts/missing-ignore-scripts"


# --- a .env line past 1 KB is comment-stripped like any other (#508) ---
# `strip_hash_comments` used to return a >1 KB line with its comment attached, so a setting that
# appears only in that comment read as real protection: the #533/#685 class, reopened by padding.
_LONG_VALUE = "a" * 1100  # no `#`, no quotes


def test_npm_ignore_scripts_env_var_only_in_long_line_comment_still_fires(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text('{"name": "app"}', encoding="utf-8")
    (tmp_path / ".env").write_text(
        f"BUILD_TAG={_LONG_VALUE}  # NPM_CONFIG_IGNORE_SCRIPTS=true once we roll this out\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"frontend"})
    findings = NpmIgnoreScriptsGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "npm-ignore-scripts/missing-ignore-scripts"


def test_npm_ignore_scripts_env_var_real_setting_with_long_comment_silences(tmp_path: Path) -> None:
    # FP-bait for that widening: stripping the long comment must leave the real setting before it.
    (tmp_path / "package.json").write_text('{"name": "app"}', encoding="utf-8")
    (tmp_path / ".env").write_text(
        f"NPM_CONFIG_IGNORE_SCRIPTS=true  # {_LONG_VALUE}\n", encoding="utf-8"
    )
    profile = mkprofile(tmp_path, features={"frontend"})
    assert NpmIgnoreScriptsGuard().run(tmp_path, profile) == []


# --- #539: the CI pragma covers one install, and backslash continuations are joined ---

_P = "security: allow-npm-scripts"
_STEPS = "jobs:\n  b:\n    steps:\n"  # lines 1-3, so the first step is line 4


def _wf_locations(tmp_path: Path, workflow: str) -> list[str]:
    """`_ci_locations` for a whole workflow file, written byte-for-byte (`newline=""`) so a CRLF
    fixture stays CRLF on every platform. Same hardened `.npmrc` and posix-normalized output."""
    (tmp_path / "package.json").write_text('{"name": "app"}', encoding="utf-8")
    (tmp_path / ".npmrc").write_text("ignore-scripts=true\n", encoding="utf-8")
    wf_dir = tmp_path / ".github" / "workflows"
    wf_dir.mkdir(parents=True, exist_ok=True)
    (wf_dir / "ci.yml").write_text(workflow, encoding="utf-8", newline="")
    profile = mkprofile(tmp_path, features={"frontend"})
    return [f.location.replace("\\", "/") for f in NpmIgnoreScriptsGuard().run(tmp_path, profile)]


def test_npm_ignore_scripts_ci_pragma_is_line_scoped(tmp_path: Path) -> None:
    # The reported bug: one step's pragma silenced every install in the workflow file, including
    # a later step nobody opted out. The second step must still fire.
    wf = _STEPS + f"      - run: npm install  # {_P}\n      - run: npm ci\n"
    assert _wf_locations(tmp_path, wf) == [".github/workflows/ci.yml:5"]


def test_npm_ignore_scripts_ci_pragma_mention_in_comment_does_not_blind_file(tmp_path: Path) -> None:
    # A comment DECLINING the pragma is a mention, not an opt-out of any install.
    wf = f"# do NOT add {_P} here\n" + _STEPS + "      - run: npm install\n      - run: npm install\n"
    assert _wf_locations(tmp_path, wf) == [".github/workflows/ci.yml:5", ".github/workflows/ci.yml:6"]


def test_npm_ignore_scripts_ci_pragma_in_string_does_not_suppress(tmp_path: Path) -> None:
    # #424 / #1040: the phrase inside a quoted string is not a comment, so it is not a pragma.
    wf = _STEPS + f'      - run: echo "{_P}"\n      - run: npm install\n'
    assert _wf_locations(tmp_path, wf) == [".github/workflows/ci.yml:5"]


def test_npm_ignore_scripts_ci_trailing_pragma_does_not_cover_next_command(tmp_path: Path) -> None:
    # A pragma TRAILING a command covers that command only. The naive `lineno - 1` reach
    # (jwt_alg.py's shape) would let it cover the next line too: the bug above, one line over.
    wf = _STEPS + f"      - run: |\n          npm install  # {_P}\n          npm ci\n"
    assert _wf_locations(tmp_path, wf) == [".github/workflows/ci.yml:6"]


def test_npm_ignore_scripts_ci_pragma_in_run_block_shell_comment_silences(tmp_path: Path) -> None:
    # FP bait, rule 4: a shell comment inside a `run: |` script is a real opt-out. The `yaml`
    # comment view reads a block scalar as content and would void it; the guard reads `hash`.
    wf = _STEPS + f"      - run: |\n          npm install  # {_P}\n          echo done\n"
    assert _wf_locations(tmp_path, wf) == []


def test_npm_ignore_scripts_ci_pragma_on_continuation_line_silences(tmp_path: Path) -> None:
    # FP bait: a pragma at the end of a continued command sits on a later PHYSICAL line. The
    # pragma is judged on the joined text, which carries it onto the command's anchor line.
    wf = _STEPS + f"      - run: |\n          npm install \\\n            --save foo  # {_P}\n"
    assert _wf_locations(tmp_path, wf) == []


def test_npm_ignore_scripts_ci_pragma_comment_line_above_silences(tmp_path: Path) -> None:
    # FP bait: a comment-only pragma line directly above the step covers it (the YAML habit).
    assert _wf_locations(tmp_path, _STEPS + f"      # {_P}\n      - run: npm install\n") == []
    # ...and only the line directly below it: the install above the pragma line still fires.
    wf = _STEPS + f"      - run: |\n          npm install\n          # {_P}\n          npm ci\n"
    assert _wf_locations(tmp_path, wf) == [".github/workflows/ci.yml:5"]


def test_npm_ignore_scripts_ci_far_pragma_no_longer_silences(tmp_path: Path) -> None:
    # The intended behavior change (#539, BREAKING): a pragma that is neither on the install nor
    # on the comment line directly above it no longer reaches it. Pinned so a later change
    # cannot quietly restore file scope. Top of file:
    wf = f"# {_P}\n" + _STEPS + "      - run: npm install\n"
    assert _wf_locations(tmp_path, wf) == [".github/workflows/ci.yml:5"]
    # ...and above `- name:`, two lines from the `run:` it was meant for:
    wf = _STEPS + f"      # {_P}\n      - name: build\n        run: npm install\n"
    assert _wf_locations(tmp_path, wf) == [".github/workflows/ci.yml:6"]


def test_npm_ignore_scripts_ci_backslash_continuation_flag_silent(tmp_path: Path) -> None:
    # Item 2: a flag on a backslash-continuation line is passed to the same command.
    for wf in (
        _STEPS + "      - run: |\n          npm install \\\n            --ignore-scripts\n",
        _STEPS + "      - run: |\n          npm install \\\n            --save foo \\\n            --ignore-scripts\n",
        (_STEPS + "      - run: |\n          npm install \\\n            --ignore-scripts\n").replace("\n", "\r\n"),
    ):
        assert _wf_locations(tmp_path, wf) == [], wf


def test_npm_ignore_scripts_ci_backslash_continuation_without_flag_fires(tmp_path: Path) -> None:
    # Rule 1's other half for the join: a continued install with no flag (or whose flag belongs
    # to a later command) still fires, anchored at the command's first physical line.
    for wf in (
        _STEPS + "      - run: |\n          npm install \\\n            --save-dev foo\n",
        _STEPS + "      - run: |\n          npm install \\\n            && npm ci --ignore-scripts\n",
    ):
        assert _wf_locations(tmp_path, wf) == [".github/workflows/ci.yml:5"], wf


def test_npm_ignore_scripts_ci_continuation_keeps_separator_semantics(tmp_path: Path) -> None:
    # The join composes with the #533/#540 lookahead: a git-ref `#` and a quoted `&` stay inside
    # the exemption span across the join...
    for wf in (
        _STEPS + "      - run: |\n          npm install git+https://h/r.git#v1 \\\n            --ignore-scripts\n",
        _STEPS + '      - run: |\n          npm install --registry "https://r/?a=1&b=2" \\\n'
        "            --ignore-scripts\n",
    ):
        assert _wf_locations(tmp_path, wf) == [], wf
    # ...and a flag on a comment line, or after a comment, is still not passed to the install.
    for wf in (
        _STEPS + "      - run: |\n          npm install \\\n            # --ignore-scripts\n",
        _STEPS + "      - run: |\n          npm install  # note \\\n            --ignore-scripts\n",
    ):
        assert _wf_locations(tmp_path, wf) == [".github/workflows/ci.yml:5"], wf
