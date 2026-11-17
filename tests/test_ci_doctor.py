"""Tests for `agentsec ci doctor` — the generated-CI preflight."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from agentsec.ci.doctor import Diagnosis, diagnose, has_errors, render
from agentsec.cli import main

_FIXTURE = Path(__file__).resolve().parent / "fixtures" / "saas_sample"
_SHA = "0123456789abcdef0123456789abcdef01234567"


def _wf(repo: Path, text: str) -> None:
    d = repo / ".github" / "workflows"
    d.mkdir(parents=True, exist_ok=True)
    (d / "agentsec-audit.yml").write_text(text, encoding="utf-8")


def test_no_workflow_warns(tmp_path: Path) -> None:
    diags = diagnose(tmp_path)
    assert len(diags) == 1 and diags[0].level == "warn"
    assert not has_errors(diags)


def test_unauthenticated_git_install_warns(tmp_path: Path) -> None:
    _wf(tmp_path, 'steps:\n  - run: pip install "git+https://github.com/o/agentsec@main"\n'
                  '  - run: agentsec audit . --deterministic --fail-on high\n')
    diags = diagnose(tmp_path)
    assert any(d.level == "warn" and "no token" in d.title for d in diags)


def test_nondeterministic_gate_warns(tmp_path: Path) -> None:
    _wf(tmp_path, 'steps:\n  - run: pip install "agentsec"\n'
                  '  - run: agentsec audit . --fail-on high\n')
    diags = diagnose(tmp_path)
    assert any(d.level == "warn" and "non-deterministic" in d.title for d in diags)


def test_missing_baseline_is_error(tmp_path: Path) -> None:
    _wf(tmp_path, 'steps:\n  - run: pip install "agentsec"\n'
                  '  - run: agentsec audit mod --deterministic --baseline-snapshot mod/agentsec-baseline.json --fail-on high\n')
    diags = diagnose(tmp_path)
    assert has_errors(diags)
    assert any(d.level == "error" and "missing baseline" in d.title for d in diags)


_SQL_ROW: dict[str, object] = {
    "fingerprint": "0f25d83d74e82ae1", "check_id": "policy-no-role-scope",
    "rule": "policy-no-role-scope/no-to-clause", "severity": "high",
    "location": "sql/2-user_profiles_rls.sql:2", "title": "t", "message": "",
}


def _baselined_gate(repo: Path, row: dict[str, object]) -> None:
    _wf(repo, 'steps:\n  - run: pip install "agentsec"\n'
              '  - run: agentsec audit . --deterministic --baseline-snapshot agentsec-baseline.json '
              '--fail-on high\n')
    (repo / "agentsec-baseline.json").write_text(
        json.dumps({"version": 2, "findings": [row]}), encoding="utf-8"
    )


def test_pre_853_baseline_with_a_schema_row_warns(tmp_path: Path) -> None:
    """A committed baseline saved before #853 cannot gate a superseded finding that comes back live
    (#1038 round 1, M1). Doctor already inspects the baseline, so it says so, as a warning."""
    _baselined_gate(tmp_path, _SQL_ROW)
    diags = diagnose(tmp_path)
    warn = [d for d in diags if d.level == "warn" and "predates the superseded verdict" in d.title]
    assert warn, render(diags)
    assert "with the schema dump in place, if the repo ships one" in warn[0].fix and "--save-snapshot agentsec-baseline.json" in warn[0].fix
    assert not has_errors(diags)


@pytest.mark.parametrize("row", [
    {**_SQL_ROW, "historical": True},                    # re-saved since #853
    {**_SQL_ROW, "historical": False},
    {**_SQL_ROW, "check_id": "command-injection", "rule": "command-injection", "location": "app.py:3"},
])
def test_resaved_or_non_schema_baseline_does_not_warn(tmp_path: Path, row: dict[str, object]) -> None:
    """FP-bait: a re-saved baseline, or an old one with no finding a dump could supersede, is fine."""
    _baselined_gate(tmp_path, row)
    diags = diagnose(tmp_path)
    assert any(d.level == "ok" and "baseline snapshot present" in d.title for d in diags)
    assert not any("predates" in d.title for d in diags), render(diags)


def test_codeql_upload_warns(tmp_path: Path) -> None:
    _wf(tmp_path, 'steps:\n  - run: pip install "agentsec"\n'
                  '  - run: agentsec audit . --deterministic --fail-on high\n'
                  '  - uses: github/codeql-action/upload-sarif@v3\n')
    diags = diagnose(tmp_path)
    assert any(d.level == "warn" and "code scanning" in d.title for d in diags)


@pytest.mark.slow
def test_freshly_generated_scoped_baselined_private_is_clean(tmp_path: Path) -> None:
    """The north-star install (scoped + baseline + private token) passes doctor cleanly.

    `--yes` accepts the baseline non-interactively: the fixture has existing HIGH findings,
    and `--with-baseline` requires a conscious accept before recording them as non-gating (see
    `_confirm_baseline`). The ratchet model keeps them visible every run and fails only on NEW
    findings — addressing the day-one blind-spot Marconi raised on #176."""
    (tmp_path / "mod").mkdir()
    for f in _FIXTURE.rglob("*"):
        if f.is_file():
            dst = tmp_path / "mod" / f.relative_to(_FIXTURE)
            dst.parent.mkdir(parents=True, exist_ok=True)
            dst.write_bytes(f.read_bytes())
    rc = main(["ci", "add", "self-audit", str(tmp_path), "--path", "mod", "--action-sha", _SHA,
               "--with-baseline", "--yes", "--install-secret", "AGENTSEC_PAT"])
    assert rc == 0
    diags = diagnose(tmp_path)
    assert not has_errors(diags)
    assert not any(d.level == "warn" for d in diags), render(diags)
    assert any(d.level == "ok" and "deterministic" in d.title for d in diags)
    assert any(d.level == "ok" and d.title == "baseline snapshot present: mod/agentsec-baseline.json"
               for d in diags), render(diags)


def test_pypi_distribution_name_is_recognised_as_an_install(tmp_path: Path) -> None:
    """The PyPI distribution is `ai-agent-security`, which does NOT contain "agentsec".

    A substring check on the console-script name alone stops seeing the install line entirely, so
    every install-auth diagnosis silently vanishes rather than failing. Confirmed red against the
    pre-rename check.
    """
    _wf(tmp_path, 'steps:\n  - run: pip install "ai-agent-security"\n'
                  '  - run: agentsec audit . --deterministic --fail-on high\n')
    titles = [d.title for d in diagnose(tmp_path)]
    assert any("install is authenticated or public" in x for x in titles), (
        f"the install line was not recognised at all; diagnoses were {titles}"
    )


def test_a_non_agentsec_install_line_is_not_claimed(tmp_path: Path) -> None:
    """FP-bait for the widening above: broadening the match must not swallow other installs."""
    _wf(tmp_path, 'steps:\n  - run: pip install "requests"\n'
                  '  - run: agentsec audit . --deterministic --no-fail\n')
    titles = [d.title for d in diagnose(tmp_path)]
    assert not any("install is authenticated or public" in x for x in titles), (
        f"an unrelated pip install was claimed as the agentsec install; diagnoses were {titles}"
    )


# --- install-unpinned / install-token-in-url (CI plan PR 1, task 1.5) -------------------------

# A copy of the workflow the copier template rendered with its defaults (`agentsec_ref: main`).
# Kept verbatim so a leftover copier user still gets a signal from doctor once `templates/` is
# gone: it installs agentsec from the moving `@main` branch.
_COPIER_RENDERED = """\
name: Security (demo · agentsec)

# Generated by agentsec's copier template. Re-run `copier update` to refresh.
on:
  pull_request:
  push:
    branches: ["main"]

permissions:
  contents: read

jobs:
  agentsec:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout
        uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd  # v6.0.2
        with:
          fetch-depth: 0  # gitleaks needs history

      - name: Set up Python 3.12
        uses: actions/setup-python@a309ff8b426b58ec0e2a45f0f869d46889d02405  # v6.2.0
        with:
          python-version: "3.12"

      - name: Install agentsec
        run: pip install "git+https://github.com/zard49/ai-agent-security@main"

      - name: agentsec audit (SARIF + gate)
        run: agentsec audit . --sarif-out agentsec.sarif --fail-on high
"""

# The pre-PR-1 `--install-secret` render: the PAT inlined into the pip URL, at `@main`.
_OLD_PRIVATE_RENDER = (
    'steps:\n  - run: pip install "git+https://${{ secrets.AGENTSEC_PAT }}@github.com/zard49/'
    'ai-agent-security@main"\n  - run: agentsec audit . --deterministic --fail-on high\n'
)


def _install_wf(repo: Path, url: str) -> None:
    """A workflow that installs from `url` and runs a deterministic gate (doctor only reads
    workflows that mention agentsec, and the distribution name `ai-agent-security` does not)."""
    _wf(repo, f'steps:\n  - run: pip install "{url}"\n'
              '  - run: agentsec audit . --deterministic --fail-on high\n')


def _checks(diags: list[Diagnosis]) -> set[str]:
    return {d.check for d in diags} - {""}


def test_copier_rendered_workflow_trips_install_unpinned(tmp_path: Path) -> None:
    _wf(tmp_path, _COPIER_RENDERED)
    diags = diagnose(tmp_path)
    unpinned = [d for d in diags if d.check == "install-unpinned"]
    assert len(unpinned) == 1 and unpinned[0].level == "warn", render(diags)
    assert "@main" in unpinned[0].title
    assert "install-token-in-url" not in _checks(diags)


def test_old_private_render_trips_both_checks_and_is_not_called_authenticated(tmp_path: Path) -> None:
    _wf(tmp_path, _OLD_PRIVATE_RENDER)
    diags = diagnose(tmp_path)
    assert {"install-unpinned", "install-token-in-url"} <= _checks(diags), render(diags)
    token = next(d for d in diags if d.check == "install-token-in-url")
    assert token.level == "warn" and "--install-secret NAME --force" in token.fix
    assert not any("authenticated" in d.title for d in diags), render(diags)


@pytest.mark.parametrize("secret", [None, "AGENTSEC_PAT"])
def test_fresh_render_trips_neither_install_check(tmp_path: Path, secret: str | None) -> None:
    """FP-bait: what `ci add` renders today (the action at a release commit SHA; the private
    form checks it out with a token) is clean."""
    argv = ["ci", "add", "self-audit", str(tmp_path), "--action-sha", _SHA]
    if secret:
        argv += ["--install-secret", secret]
    assert main(argv) == 0
    diags = diagnose(tmp_path)
    assert not ({"install-unpinned", "install-token-in-url"} & _checks(diags)), render(diags)
    if secret:
        assert any(d.level == "ok" and "checkout is authenticated" in d.title for d in diags), render(diags)
        assert not any("no token" in d.title for d in diags), render(diags)


@pytest.mark.parametrize("ref", ["v0.21.70", "v1.2.3-rc1", "0123456789abcdef0123456789abcdef01234567"])
def test_pinned_refs_do_not_trip_install_unpinned(tmp_path: Path, ref: str) -> None:
    _install_wf(tmp_path, f"git+https://github.com/zard49/ai-agent-security@{ref}")
    assert "install-unpinned" not in _checks(diagnose(tmp_path))


@pytest.mark.parametrize("url", [
    "git+https://github.com/zard49/ai-agent-security@main",
    "git+https://github.com/zard49/ai-agent-security@master",
    "git+https://github.com/zard49/ai-agent-security",           # no ref: the default branch
    "git+https://github.com/zard49/ai-agent-security.git@dev#egg=ai-agent-security",
    "git+https://github.com/o/agentsec@0123abc",                    # short SHA: not a full pin
    "git+ssh://git@github.com/zard49/ai-agent-security@main",
])
def test_branch_refs_trip_install_unpinned(tmp_path: Path, url: str) -> None:
    _install_wf(tmp_path, url)
    assert "install-unpinned" in _checks(diagnose(tmp_path))


@pytest.mark.parametrize(("ref", "unpinned"), [("${AGENTSEC_SHA}", False), ("main", True)])
def test_a_variable_ref_and_a_continuation_line_url_are_handled(
    tmp_path: Path, ref: str, unpinned: bool,
) -> None:
    """HWH's production install: `uv tool install` on one line, the token-free URL on the next,
    with the SHA from a variable. Neither check may fire on it (the ref is pinned upstream); the
    same shape at `@main` must still trip install-unpinned (the URL on a continuation line is seen)."""
    _wf(tmp_path, (
        "steps:\n  - env:\n      AGENTSEC_PAT: ${{ secrets.AGENTSEC_PAT }}\n    run: |\n"
        '      GIT_ASKPASS="$ASKPASS" GIT_TERMINAL_PROMPT=0 \\\n'
        "        uv tool install --force \\\n"
        f'        "git+https://x-access-token@github.com/zard49/ai-agent-security@{ref}"\n'
    ))
    checks = _checks(diagnose(tmp_path))
    assert "install-token-in-url" not in checks
    assert ("install-unpinned" in checks) is unpinned


@pytest.mark.parametrize("userinfo", [
    "${{ secrets.AGENTSEC_PAT }}",
    "${{ env.GH_TOKEN }}",
    "x-access-token:${{ secrets.AGENTSEC_PAT }}",
    "$GH_TOKEN",
    "${GH_TOKEN}",
    "ghp_" + "a" * 36,
    "github_pat_" + "b" * 30,
])
def test_token_in_url_fires_on_every_credential_shape(tmp_path: Path, userinfo: str) -> None:
    _install_wf(tmp_path, f"git+https://{userinfo}@github.com/zard49/ai-agent-security@v0.21.70")
    diags = diagnose(tmp_path)
    assert "install-token-in-url" in _checks(diags), render(diags)
    assert "install-unpinned" not in _checks(diags)


def test_token_free_username_alone_is_not_a_token(tmp_path: Path) -> None:
    _install_wf(tmp_path, "git+https://x-access-token@github.com/zard49/ai-agent-security@v0.21.70")
    assert "install-token-in-url" not in _checks(diagnose(tmp_path))


def test_install_checks_ignore_comments_and_other_repos(tmp_path: Path) -> None:
    """FP-bait: a URL quoted in a comment is not an install, and a token in some other repo's
    URL is not an agentsec install leak."""
    old = 'pip install "git+https://${{ secrets.X }}@github.com/zard49/ai-agent-security@main"'
    body = (
        'steps:\n  - run: pip install "git+https://${{ secrets.X }}@github.com/acme/private-lib@main"\n'
        '  - run: agentsec audit . --deterministic --fail-on high\n'
    )
    _wf(tmp_path, f"# old form: {old}\n{body}")
    assert not ({"install-unpinned", "install-token-in-url"} & _checks(diagnose(tmp_path)))
    # positive control: the same URL as a real step trips both
    _wf(tmp_path, f"{body}  - run: {old}\n")
    assert {"install-unpinned", "install-token-in-url"} <= _checks(diagnose(tmp_path))


# --- agentsec's GitHub Action (what `ci add self-audit` renders) -------------------------------

def _action_wf(repo: Path, uses: str, with_lines: str = "", *, name_first: bool = False) -> None:
    head = "    - name: agentsec audit\n      uses: " if name_first else "    - uses: "
    body = f"{head}{uses}\n" + (f"      with:\n{with_lines}" if with_lines else "")
    _wf(repo, "jobs:\n  audit:\n    runs-on: ubuntu-latest\n    steps:\n"
              "    - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd  # v6.0.2\n"
              f"{body}")


@pytest.mark.parametrize(("ref", "unpinned"), [
    (_SHA, False),
    ("v0.22.0", True),          # a tag can be moved, and actions-sha-pin fails the gate on it
    ("main", True),
    ("0123abc", True),          # a short SHA is not a pin
])
@pytest.mark.parametrize("name_first", [False, True])
def test_a_remote_action_use_must_name_a_full_commit_sha(
    tmp_path: Path, ref: str, unpinned: bool, name_first: bool,
) -> None:
    _action_wf(tmp_path, f"zard49/ai-agent-security@{ref}  # v0.22.0", name_first=name_first)
    diags = diagnose(tmp_path)
    assert ("install-unpinned" in _checks(diags)) is unpinned, render(diags)
    # a remote use of a private repo is the wall the token checkout exists for: always said, as
    # information (doctor cannot know the repo's visibility offline), never as a warning
    assert any(d.level == "info" and "used from another repository" in d.title for d in diags)
    assert ("1 warning(s)" in render(diags)) is unpinned, render(diags)


@pytest.mark.parametrize("owner", ["Zard-Lab", "zard49", "a-fork"])
def test_agentsec_is_recognised_under_any_owner(tmp_path: Path, owner: str) -> None:
    """The public repo moved owners at the PyPI cutover; pins to the old private repo (HWH) must
    still be diagnosed, so recognition goes by repo name, not by AGENTSEC_REPO_SLUG's owner."""
    _action_wf(tmp_path / "action", f"{owner}/ai-agent-security@v0.22.2")
    assert "install-unpinned" in _checks(diagnose(tmp_path / "action"))
    _install_wf(tmp_path / "pip", f"git+https://github.com/{owner}/ai-agent-security@main")
    assert "install-unpinned" in _checks(diagnose(tmp_path / "pip"))


def test_another_repo_of_the_same_owner_is_not_agentsec(tmp_path: Path) -> None:
    # the step mentions agentsec, so doctor reads the workflow; the unpinned `uses:` is not ours
    _action_wf(tmp_path, "Zard-Lab/other-tool@v1  # runs before agentsec")
    assert "install-unpinned" not in _checks(diagnose(tmp_path))


@pytest.mark.parametrize(("ref_line", "unpinned"), [
    (f"        ref: {_SHA}  # v0.22.0\n", False),
    ("        ref: ${{ inputs.agentsec-ref }}\n", False),   # an expression: can't tell here
    ("        ref: v0.22.0\n", True),
    ("", True),                                          # no ref: the default branch
])
def test_the_private_checkout_ref_must_name_a_full_commit_sha(
    tmp_path: Path, ref_line: str, unpinned: bool,
) -> None:
    _wf(tmp_path, "jobs:\n  audit:\n    steps:\n"
                  "    - name: Check out the agentsec action\n"
                  "      uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd  # v6.0.2\n"
                  "      with:\n        repository: zard49/ai-agent-security\n" + ref_line +
                  "        token: ${{ secrets.AGENTSEC_PAT }}\n        path: .agentsec-action\n"
                  "    - uses: ./.agentsec-action\n")
    diags = diagnose(tmp_path)
    assert ("install-unpinned" in _checks(diags)) is unpinned, render(diags)
    assert not any("used from another repository" in d.title for d in diags)  # local use


def test_a_private_checkout_without_a_token_warns_and_one_with_a_token_is_ok(tmp_path: Path) -> None:
    step = ("jobs:\n  audit:\n    steps:\n"
            "    - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd  # v6.0.2\n"
            f"      with:\n        repository: zard49/ai-agent-security\n        ref: {_SHA}\n")
    _wf(tmp_path, step + "        path: .agentsec-action\n    - uses: ./.agentsec-action\n")
    assert any(d.level == "warn" and "checked out with no token" in d.title for d in diagnose(tmp_path))
    _wf(tmp_path, step + "        token: ${{ secrets.AGENTSEC_PAT }}\n        path: .agentsec-action\n"
                         "    - uses: ./.agentsec-action\n")
    diags = diagnose(tmp_path)
    assert any(d.level == "ok" and "checkout is authenticated" in d.title for d in diags), render(diags)
    assert not any("no token" in d.title for d in diags)


def test_the_actions_baseline_snapshot_must_exist(tmp_path: Path) -> None:
    """The action carries the snapshot as an input, not a `--baseline-snapshot` flag; doctor must
    still see a missing one (it would otherwise go silent on every new render)."""
    _action_wf(tmp_path, f"zard49/ai-agent-security@{_SHA}",
               "        path: mod\n        baseline-snapshot: mod/agentsec-baseline.json  # ratchet\n")
    diags = diagnose(tmp_path)
    assert has_errors(diags)
    assert any(d.title == "gate references a missing baseline snapshot: mod/agentsec-baseline.json"
               for d in diags), render(diags)
    (tmp_path / "mod").mkdir()
    (tmp_path / "mod" / "agentsec-baseline.json").write_text("[]", encoding="utf-8")
    diags = diagnose(tmp_path)
    assert not has_errors(diags), render(diags)
    assert any(d.title == "baseline snapshot present: mod/agentsec-baseline.json" for d in diags)


@pytest.mark.parametrize(("with_lines", "verdict"), [
    ("", "ok"),                                               # default scanners: deterministic
    ("        scanners: guards-only\n", "ok"),
    ("        scanners: all\n", "warn"),
    ("        scanners: all\n        mode: advisory\n", None),   # advisory never gates: not judged
])
def test_the_actions_gate_determinism(tmp_path: Path, with_lines: str, verdict: str | None) -> None:
    _action_wf(tmp_path, f"zard49/ai-agent-security@{_SHA}", with_lines + "        fail-on: high\n")
    diags = [d for d in diagnose(tmp_path) if "deterministic" in d.title]
    assert [d.level for d in diags] == ([verdict] if verdict else []), render(diags)


def test_action_checks_ignore_other_actions_and_block_scalar_bodies(tmp_path: Path) -> None:
    """FP-bait: another action's tag, another repo's checkout, and lines inside a block scalar that
    look like keys are none of these checks' business."""
    _wf(tmp_path, "jobs:\n  audit:\n    steps:\n"
                  "    - uses: actions/setup-python@v6\n      with:\n        python-version: '3.12'\n"
                  "    - uses: actions/checkout@v6\n      with:\n        repository: acme/tools\n"
                  f"    - uses: zard49/ai-agent-security@{_SHA}\n      with:\n"
                  "        exclude: |\n          baseline-snapshot: nope.json\n          scanners: all\n"
                  "        top: '5'\n")
    diags = diagnose(tmp_path)
    assert "install-unpinned" not in _checks(diags), render(diags)
    assert not has_errors(diags), render(diags)
    assert [d.level for d in diags if "deterministic" in d.title] == ["ok"]


# --- round-1 review of #1173: L1 (default render), L2 (look-alikes), L3 (with: shapes) --------

def test_the_default_render_is_all_clear_with_an_info_note(tmp_path: Path) -> None:
    """R1 L1: what `ci add self-audit` writes by default must not end in a warning; the remote-use
    caveat is an `info` line that does not count in the verdict."""
    assert main(["ci", "add", "self-audit", str(tmp_path), "--action-sha", _SHA]) == 0
    diags = diagnose(tmp_path)
    assert render(diags).rstrip().endswith("all clear"), render(diags)
    assert [d.title for d in diags if d.level == "info"] == ["agentsec action used from another repository"]
    assert not has_errors(diags)


@pytest.mark.parametrize("step", [
    "    - uses: acme/agentsec-scan-action@v1\n      with:\n        scanners: all\n",
    "    - uses: acme/ai-agent-security-ci@main\n",
    "    - uses: zard49/ai-agent-security/.github/actions/other@main\n",       # a sub-action, not ours
    "    - uses: ./tools/agentsec-lint\n      with:\n        scanners: all\n",  # no agentsec checkout here
    "    - uses: actions/checkout@v6\n      with:\n        repository: acme/agentsec-tools\n        ref: main\n",
])
def test_look_alike_actions_and_repos_are_not_agentsecs(tmp_path: Path, step: str) -> None:
    """R1 L2 FP-bait: a name that merely contains agentsec's is someone else's action or repo."""
    _wf(tmp_path, "jobs:\n  audit:\n    name: agentsec\n    steps:\n" + step)
    diags = diagnose(tmp_path)
    assert not [d for d in diags if d.level != "ok" or "deterministic" in d.title], render(diags)


def test_a_reusable_workflow_of_agentsecs_repo_is_not_its_action(tmp_path: Path) -> None:
    _wf(tmp_path, "jobs:\n  audit:\n    uses: zard49/ai-agent-security/.github/workflows/r.yml@main\n")
    diags = diagnose(tmp_path)
    assert "install-unpinned" not in _checks(diags), render(diags)
    assert not any("another repository" in d.title for d in diags)


@pytest.mark.parametrize("uses", ["myorg/ai-agent-security@v1", "Zard49/AI-Agent-Security.git@main"])
def test_a_fork_or_respelling_of_agentsecs_repo_is_still_checked(tmp_path: Path, uses: str) -> None:
    """R1 L2 still-fires: the exact repo name under any owner (a fork) is agentsec's action."""
    _action_wf(tmp_path, uses, "        scanners: all\n")
    diags = diagnose(tmp_path)
    assert "install-unpinned" in _checks(diags), render(diags)
    assert any(d.title == "gate is non-deterministic" for d in diags)


def test_a_local_use_counts_only_where_agentsecs_repo_was_checked_out(tmp_path: Path) -> None:
    """R1 L2: `uses: ./<dir>` is agentsec's action when a checkout of agentsec's repo put it there,
    whatever the directory is called."""
    _wf(tmp_path, "jobs:\n  audit:\n    steps:\n"
                  "    - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd  # v6.0.2\n"
                  f"      with:\n        repository: zard49/ai-agent-security\n        ref: {_SHA}\n"
                  "        token: ${{ secrets.T }}\n        path: vendor/tooling\n"
                  "    - uses: ./vendor/tooling/\n      with:\n        scanners: all\n")
    assert any(d.title == "gate is non-deterministic" for d in diagnose(tmp_path))


@pytest.mark.parametrize("with_block", [
    "      with: { scanners: all, baseline-snapshot: nope.json }\n",
    "      with: {scanners: 'all', baseline-snapshot: \"nope.json\"}  # inputs\n",
    "      with:  # the inputs\n        scanners: all\n        baseline-snapshot: nope.json\n",
])
def test_flow_and_commented_with_blocks_are_read(tmp_path: Path, with_block: str) -> None:
    """R1 L3: these shapes used to read as an empty `with:`, so doctor reported a deterministic
    gate and no missing baseline (a failure that presents as success)."""
    _wf(tmp_path, f"jobs:\n  audit:\n    steps:\n    - uses: zard49/ai-agent-security@{_SHA}\n{with_block}")
    diags = diagnose(tmp_path)
    assert any(d.title == "gate is non-deterministic" for d in diags), render(diags)
    assert any(d.title == "gate references a missing baseline snapshot: nope.json" for d in diags)
    assert not any(d.title == "gate is deterministic" for d in diags)


@pytest.mark.parametrize("with_value", ["*defaults", "{ exclude: 'a, b' }", "{ x: [1, 2] }"])
def test_an_unreadable_with_is_said_not_passed(tmp_path: Path, with_value: str) -> None:
    """R1 L3: a `with:` the text reader cannot take apart gets an info line instead of an `ok`."""
    _wf(tmp_path, f"jobs:\n  audit:\n    steps:\n    - uses: zard49/ai-agent-security@{_SHA}\n"
                  f"      with: {with_value}\n")
    diags = diagnose(tmp_path)
    assert any(d.level == "info" and "could not read the inputs" in d.title for d in diags), render(diags)
    assert not any("deterministic" in d.title for d in diags)


def test_a_quoted_baseline_path_with_an_apostrophe_is_read_back(tmp_path: Path) -> None:
    """R1 L5: the renderer writes `baseline-snapshot: 'o''brien #mod/...'`; doctor must read it as
    the real path (the `''` escape and the `#` inside quotes)."""
    from agentsec.ci.library import derive_params, get_component
    from agentsec.ci.render import render as render_tmpl
    from agentsec.detect import detect
    c = get_component("self-audit")
    params = derive_params(c, detect(tmp_path), audit_path="o'brien #mod", with_baseline=True,
                           action_sha=_SHA)
    _wf(tmp_path, render_tmpl((c.dir / "files/.github/workflows/agentsec-audit.yml.tmpl")
                              .read_text(encoding="utf-8"), params))
    snap = tmp_path / "o'brien #mod" / "agentsec-baseline.json"
    snap.parent.mkdir()
    snap.write_text("[]", encoding="utf-8")
    diags = diagnose(tmp_path)
    assert any(d.title == "baseline snapshot present: o'brien #mod/agentsec-baseline.json"
               for d in diags), render(diags)
    assert not has_errors(diags)
