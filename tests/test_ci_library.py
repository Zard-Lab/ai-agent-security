"""Tests for the CI component library, incl. the CRITICAL secret scan over the shipped component files.
Its project-specific half (names of our own infrastructure) is the private
`tests/test_ci_library_sanitization.py`."""
from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest
import yaml

from agentsec import __version__
from agentsec.ci.library import (
    COMPONENTS_DIR,
    derive_params,
    get_component,
    install,
    load_components,
    planned_files,
)
from agentsec.ci.render import render, required_tokens
from agentsec.detect import detect
from tests.conftest import mkprofile

_FIXTURE = Path(__file__).resolve().parent / "fixtures" / "saas_sample"
_EXPECTED_IDS = {
    "react-doctor", "secret-scan", "dockerfile-lint", "python-sec", "frontend-sec",
    "dast", "db-lint", "container-cve", "type-check", "self-audit",
    "garak", "promptfoo", "scorecard",
}

# Secret shapes that must NEVER appear in any shipped component file: the user requirement is no API
# keys, no credentials, no host addresses. `${{ secrets.NAME }}` references are allowed (they reference,
# never embed). The project-specific half of this denylist names our own infrastructure, so it lives in
# the private `tests/test_ci_library_sanitization.py` and reuses `_denylist_hits` below.
_SECRET_DENYLIST: list[tuple[str, re.Pattern[str]]] = [
    ("supabase host", re.compile(r"(?<!mock-)[\w.-]*\.supabase\.co")),
    ("JWT", re.compile(r"eyJ[A-Za-z0-9_-]{10,}")),
    ("AWS key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("Slack token", re.compile(r"xox[baprs]-")),
    ("GitHub token", re.compile(r"gh[pousr]_[A-Za-z0-9]{20,}")),
    ("private key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("DSN with creds", re.compile(r"postgres(?:ql)?://[^@\s]+:[^@\s]+@")),
]
# Bare IPv4 except loopback / unspecified.
_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_IP_ALLOW = {"127.0.0.1", "0.0.0.0"}


def _denylist_hits(patterns: list[tuple[str, re.Pattern[str]]], files: list[Path], root: Path) -> list[str]:
    hits: list[str] = []
    for f in files:
        text = f.read_text(encoding="utf-8", errors="ignore")
        for lineno, line in enumerate(text.splitlines(), 1):
            hits += [f"{f.relative_to(root)}:{lineno} [{label}] {line.strip()}" for label, pat in patterns
                     if pat.search(line)]
    return hits


def _ip_hits(files: list[Path], root: Path) -> list[str]:
    hits: list[str] = []
    for f in files:
        for lineno, line in enumerate(f.read_text(encoding="utf-8", errors="ignore").splitlines(), 1):
            hits += [f"{f.relative_to(root)}:{lineno} [bare IPv4 {ip}] {line.strip()}"
                     for ip in _IPV4.findall(line) if ip not in _IP_ALLOW]
    return hits


def _all_component_files() -> list[Path]:
    return [p for p in COMPONENTS_DIR.rglob("*") if p.is_file()]


def test_no_secrets_in_shipped_components() -> None:
    files = _all_component_files()
    offenders = _denylist_hits(_SECRET_DENYLIST, files, COMPONENTS_DIR) + _ip_hits(files, COMPONENTS_DIR)
    assert not offenders, "sanitization denylist hits:\n" + "\n".join(offenders)


def test_secret_denylist_fires(tmp_path: Path) -> None:
    """Rule 1 control: the scan must flag a planted secret and address, not pass on any tree."""
    planted = tmp_path / "wf.yml"
    planted.write_text("token: ghp_" + "a" * 24 + "\nhost: 10.1.2.3\nok: 127.0.0.1\n", encoding="utf-8")
    hits = _denylist_hits(_SECRET_DENYLIST, [planted], tmp_path) + _ip_hits([planted], tmp_path)
    assert [h.split(" ")[1] for h in hits] == ["[GitHub", "[bare"]


def test_every_component_loads() -> None:
    comps = load_components()
    assert {c.id for c in comps} == _EXPECTED_IDS
    for c in comps:
        assert c.title and c.summary and c.category
        assert (c.dir / "files").is_dir()
        assert planned_files(c), f"{c.id} writes no files"


def test_applies_gating() -> None:
    fe = mkprofile(Path("/x"), features={"frontend"})
    docker = mkprofile(Path("/x"), features={"docker"})
    py = mkprofile(Path("/x"), features={"python"})
    empty = mkprofile(Path("/x"), features=set())

    assert get_component("react-doctor").applies(fe)
    assert get_component("frontend-sec").applies(fe)
    assert not get_component("react-doctor").applies(empty)
    assert get_component("dockerfile-lint").applies(docker)
    assert not get_component("dockerfile-lint").applies(fe)
    assert get_component("python-sec").applies(py)
    # secret-scan has no required features → always applies
    assert get_component("secret-scan").applies(empty)


def test_render_produces_valid_yaml() -> None:
    prof = detect(_FIXTURE)
    prof.features = set(prof.features) | {"docker"}  # so dockerfile-lint renders too
    for c in load_components():
        params = derive_params(c, prof)
        for src in (c.dir / "files").rglob("*"):
            if not (src.is_file() and src.name.endswith(".tmpl")):
                continue
            out = render(src.read_text(encoding="utf-8"), params)
            assert not required_tokens(out), f"unresolved token in {src}"
            assert "@@" not in out, f"stray @@ in {src}"
            doc = yaml.safe_load(out)
            assert doc["permissions"]["contents"] == "read", src
            assert "runs-on: ubuntu-latest" in out, src
            assert "self-hosted" not in out, src


def _templates() -> list[tuple[str, Path]]:
    return [
        (c.id, src) for c in load_components()
        for src in sorted((c.dir / "files").rglob("*.tmpl"))
    ]


def test_rendered_install_url_points_at_a_real_repo() -> None:
    """The agentsec install source must resolve to the actual home repo, not the
    not-yet-existing dynamous-community/ai-agent-security (would fail `pip install`),
    pinned to the release tag of the agentsec that rendered it.
    Single source of truth = the @@AGENTSEC_INSTALL_STEP@@ token; flip it when the tool
    moves orgs / ships to PyPI."""
    prof = detect(_FIXTURE)
    for c in load_components():
        params = derive_params(c, prof)
        for src in (c.dir / "files").rglob("*"):
            if not (src.is_file() and src.name.endswith(".tmpl")):
                continue
            raw = src.read_text(encoding="utf-8")
            out = render(raw, params)
            assert "dynamous-community/ai-agent-security" not in out, src
            # Templates that install agentsec must do so via the token, which must
            # resolve to the real home repo at the release tag.
            if "@@AGENTSEC_INSTALL_STEP@@" in raw:
                assert f'pip install "git+https://github.com/Zard-Lab/ai-agent-security@v{__version__}"' in out, src


@pytest.mark.parametrize("secret", ["", "AGENTSEC_PAT"])
def test_no_rendered_install_uses_a_branch_ref(secret: str) -> None:
    """The direction traded against: no install line, public or private, still pins `@main`
    (or any non-tag ref). A security gate must not install a moving target."""
    prof = detect(_FIXTURE)
    for cid, src in _templates():
        out = render(src.read_text(encoding="utf-8"), derive_params(get_component(cid), prof,
                                                                   install_secret=secret))
        for ln in out.splitlines():
            if "ai-agent-security" in ln and "git+" in ln:
                assert "@main" not in ln and "@master" not in ln, f"{src}: {ln.strip()}"
                assert re.search(r"ai-agent-security@v\d+\.\d+\.\d+\"", ln), f"{src}: {ln.strip()}"


def test_install_ref_is_the_release_tag_and_falls_back_only_when_unknown(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """`v<__version__>` normally; `main` only when the checklist version is unreadable."""
    from agentsec.ci import library
    assert library._agentsec_ref() == f"v{__version__}"
    assert __version__ != "0+unknown"
    monkeypatch.setattr(library, "__version__", "0+unknown")
    assert library._agentsec_ref() == "main"
    assert library.agentsec_install("") == "git+https://github.com/Zard-Lab/ai-agent-security@main"


def test_install_step_token_used_by_every_installing_template() -> None:
    """Every template that installs agentsec uses the block token, and none still carries the
    old string token (`render()` would raise on it anyway, but name it here)."""
    installing = set()
    for cid, src in _templates():
        raw = src.read_text(encoding="utf-8")
        assert "@@AGENTSEC_INSTALL@@" not in raw, src
        assert "ai-agent-security" not in raw, f"{src} hard-codes the install URL instead of the token"
        if "@@AGENTSEC_INSTALL_STEP@@" in raw:
            installing.add(cid)
            # placed alone at column 0: the block carries its own step indentation
            assert any(ln == "@@AGENTSEC_INSTALL_STEP@@" for ln in raw.splitlines()), src
    assert installing == {"dast", "db-lint", "garak", "promptfoo", "python-sec"}


@pytest.mark.parametrize("cid", ["garak", "promptfoo"])
def test_redteam_tool_install_is_its_own_step_after_agentsec(cid: str) -> None:
    """garak / promptfoo used to share one `run: |` with the agentsec install; the agentsec
    install is now the token step and the tool install follows as its own step."""
    out = render(next((get_component(cid).dir / "files").rglob("*.tmpl")).read_text(encoding="utf-8"),
                 derive_params(get_component(cid), detect(_FIXTURE), install_secret="AGENTSEC_PAT"))
    steps = yaml.safe_load(out)["jobs"][cid]["steps"]
    names = [s.get("name", "") for s in steps]
    i_agentsec = names.index("Install agentsec (private repo, token-free URL)")
    i_tool = names.index(f"Install {cid}")
    assert i_agentsec < i_tool
    tool_cmd = "pip install garak" if cid == "garak" else "npm install -g promptfoo"
    assert steps[i_tool]["run"].strip() == tool_cmd


@pytest.mark.parametrize("pm", ["npm", "pnpm", "bun"])
def test_pm_setup_block_yaml_valid(pm: str) -> None:
    prof = mkprofile(Path("/x"), features={"frontend"}, frontend_dir="web", package_managers={pm, "pip"})
    c = get_component("react-doctor")
    out = render((c.dir / "files/.github/workflows/frontend-health.yml.tmpl").read_text(encoding="utf-8"), derive_params(c, prof))
    doc = yaml.safe_load(out)
    steps = [s.get("name") for s in doc["jobs"]["react-doctor"]["steps"]]
    assert "Set up Node.js" in steps


def test_install_dry_run_writes_nothing(tmp_path: Path) -> None:
    prof = mkprofile(tmp_path, features={"frontend"}, frontend_dir="frontend")
    res = install(get_component("react-doctor"), prof, tmp_path, dry_run=True)
    assert res and all(r.action == "would-write" for r in res)
    assert not list(tmp_path.rglob("*.yml"))


def test_install_writes_and_refuses_overwrite(tmp_path: Path) -> None:
    prof = mkprofile(tmp_path, features={"frontend"}, frontend_dir="frontend")
    c = get_component("react-doctor")
    res = install(c, prof, tmp_path)
    assert all(r.action == "write" for r in res)
    wf = tmp_path / ".github" / "workflows" / "frontend-health.yml"
    cfg = tmp_path / "frontend" / "react-doctor.config.json"
    assert wf.is_file() and cfg.is_file()

    # second run without force: skip, don't clobber
    res2 = install(c, prof, tmp_path)
    assert all(r.action == "skip-exists" for r in res2)

    # force: overwrite
    res3 = install(c, prof, tmp_path, force=True)
    assert all(r.action == "write" for r in res3)


def test_frontend_dir_token_in_path(tmp_path: Path) -> None:
    """The config lands in the DETECTED frontend dir, not a hardcoded 'frontend'."""
    prof = mkprofile(tmp_path, features={"frontend"}, frontend_dir="apps/web")
    install(get_component("react-doctor"), prof, tmp_path)
    assert (tmp_path / "apps" / "web" / "react-doctor.config.json").is_file()


def _render_component_workflow(component_id: str) -> str:
    prof = detect(_FIXTURE)
    c = get_component(component_id)
    params = derive_params(c, prof)
    src = next((c.dir / "files").rglob("*.yml.tmpl"))
    return render(src.read_text(encoding="utf-8"), params)


def test_db_lint_passes_allow_remote_db() -> None:
    """Theme 7: a CI DSN is remote from the runner, so the db-lint component must
    pass --allow-remote-db or agentsec's locality guard would silently skip it."""
    out = _render_component_workflow("db-lint")
    assert "--allow-remote-db" in out
    assert yaml.safe_load(out)["permissions"]["contents"] == "read"


def test_dast_authenticated_active_opt_in() -> None:
    """Theme 7: dast stays passive by default but upgrades to an authenticated active
    scan (Supabase login + --zap-active + --allow-remote-target) when the seeded
    test-user secrets are configured."""
    out = _render_component_workflow("dast")
    assert "--supabase-login" in out and "--zap-active" in out and "--allow-remote-target" in out
    # auth is wired only via secret references, never embedded values
    assert "${{ secrets.DAST_SUPABASE_URL }}" in out
    assert "${{ secrets.DAST_TEST_USER_PASSWORD }}" in out
    assert yaml.safe_load(out)["permissions"]["contents"] == "read"


def test_render_preserves_github_expressions() -> None:
    src = "runs-on: @@RUNNER@@\nref: ${{ github.ref }}\nx: {{ keep }}"
    out = render(src, {"RUNNER": "ubuntu-latest"})
    assert "ubuntu-latest" in out
    assert "${{ github.ref }}" in out
    assert "{{ keep }}" in out


def test_render_raises_on_missing_token() -> None:
    with pytest.raises(ValueError, match="unresolved template token"):
        render("a @@MISSING@@ b", {})


# --- self-audit scoping (F2) + baseline rollout (F3) -----------------------

def test_baseline_rel_root_and_subdir() -> None:
    from agentsec.ci.library import baseline_rel
    assert baseline_rel(".") == "agentsec-baseline.json"
    assert baseline_rel("9_Agent_SaaS") == "9_Agent_SaaS/agentsec-baseline.json"


_SHA = "0123456789abcdef0123456789abcdef01234567"
_TEMPLATE = "files/.github/workflows/agentsec-audit.yml.tmpl"


def _render_self_audit(*, install_secret: str = "", advisory: bool = False, audit_path: str = ".",
                       with_baseline: bool = False, action_sha: str = _SHA) -> str:
    c = get_component("self-audit")
    params = derive_params(c, detect(_FIXTURE), install_secret=install_secret, advisory=advisory,
                           audit_path=audit_path, with_baseline=with_baseline, action_sha=action_sha)
    return render((c.dir / _TEMPLATE).read_text(encoding="utf-8"), params)


def _self_audit_steps(workflow: str) -> list[dict[str, Any]]:
    steps: list[dict[str, Any]] = yaml.safe_load(workflow)["jobs"]["agentsec-audit"]["steps"]
    return steps


def _action_step(workflow: str) -> dict[str, Any]:
    (step,) = [s for s in _self_audit_steps(workflow) if s.get("name") == "agentsec audit"]
    return step


def test_self_audit_scoped_with_baseline_renders() -> None:
    params = derive_params(get_component("self-audit"), detect(_FIXTURE), audit_path="mod",
                           with_baseline=True, action_sha=_SHA)
    assert params["AUDIT_PATH"] == "mod"
    assert params["SCOPE_PATHS"] == "\n    paths: ['mod/**']"
    assert params["BASELINE_WITH"] == "\n        baseline-snapshot: 'mod/agentsec-baseline.json'"
    out = _render_self_audit(audit_path="mod", with_baseline=True)
    assert _action_step(out)["with"] == {
        "path": "mod", "fail-on": "high", "mode": "gate", "top": "50", "python-version": "3.12",
        "coverage": "true", "baseline-snapshot": "mod/agentsec-baseline.json",
    }
    assert "paths: ['mod/**']" in out


def test_self_audit_default_calls_the_action_pinned_to_the_release_commit() -> None:
    """The default render runs agentsec's action at a full commit SHA, with the release tag as
    the comment Dependabot reads, and no longer installs or runs the CLI itself."""
    out = _render_self_audit()
    step = _action_step(out)
    assert step["uses"] == f"Zard-Lab/ai-agent-security@{_SHA}"
    assert f"uses: Zard-Lab/ai-agent-security@{_SHA}  # v{__version__}" in out
    assert step["with"] == {"path": ".", "fail-on": "high", "mode": "gate", "top": "50",
                            "python-version": "3.12", "coverage": "true"}
    assert "pip install" not in out and "GIT_ASKPASS" not in out and "secrets." not in out
    assert not [ln for ln in out.splitlines() if ln.strip().startswith(("agentsec ", "run:"))]
    assert "paths:" not in out  # no trigger scoping by default
    checkout = _self_audit_steps(out)[0]
    assert checkout["with"] == {"persist-credentials": False}


def test_self_audit_advisory_renders_advisory_mode_and_default_does_not() -> None:
    """Both directions: advisory flips the action's mode and nothing else; the default gates."""
    default, advisory = _render_self_audit(), _render_self_audit(advisory=True)
    assert _action_step(default)["with"]["mode"] == "gate"
    assert _action_step(advisory)["with"]["mode"] == "advisory"
    assert advisory.replace("\n        mode: advisory\n", "\n        mode: gate\n") == default


def test_self_audit_top_param_is_rendered() -> None:
    c = get_component("self-audit")
    assert c.params["TOP"]["default"] == "50" and c.params["ADVISORY"]["default"] == "false"
    params = derive_params(c, detect(_FIXTURE), action_sha=_SHA)
    params["TOP"] = "7"
    out = render((c.dir / _TEMPLATE).read_text(encoding="utf-8"), params)
    assert _action_step(out)["with"]["top"] == "7"


def test_self_audit_notes_describe_the_pinned_action() -> None:
    notes = get_component("self-audit").notes
    assert "installed pinned from the public repo" not in notes
    assert "GitHub Action" in notes and "commit SHA" in notes and "--action-sha" in notes
    assert "--advisory" in notes and "--install-secret" in notes


def test_self_audit_private_variant_checks_the_action_out_with_the_token() -> None:
    """Private: check the agentsec repo out at the pinned commit with the token (not persisted),
    ignore that checkout for the run, then run it as a local action. The secret expression
    appears once, as the checkout's `token:`, and never inside a URL or a shell line."""
    out = _render_self_audit(install_secret="AGENTSEC_PAT")
    steps = _self_audit_steps(out)
    names = [s.get("name") for s in steps]
    checkout = steps[names.index("Check out the agentsec action (private repo)")]
    assert checkout["uses"] == "actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd"
    assert checkout["with"] == {
        "repository": "Zard-Lab/ai-agent-security", "ref": _SHA,
        "token": "${{ secrets.AGENTSEC_PAT }}", "path": ".agentsec-action",
        "persist-credentials": False,
    }
    assert f"ref: {_SHA}  # v{__version__}" in out
    ignore = steps[names.index("Ignore the agentsec checkout in this run")]
    assert ignore["run"] == "printf '\\n/.agentsec-action/\\n' >> .gitignore"
    assert names.index("Check out the agentsec action (private repo)") < names.index(ignore["name"])
    assert names.index(ignore["name"]) < names.index("agentsec audit")
    assert _action_step(out)["uses"] == "./.agentsec-action"
    assert [ln.strip() for ln in out.splitlines() if "secrets." in ln] == [
        "token: ${{ secrets.AGENTSEC_PAT }}"
    ]
    assert not re.search(r"https://[^/\s\"']*\$\{\{", out), "a secret expression is inside a URL"
    assert "pip install" not in out and "GIT_ASKPASS" not in out


def test_the_action_checkout_pin_matches_the_templates() -> None:
    """The private checkout's pin lives in library.py, the repo checkout's in the template; a
    Dependabot-style bump of one must not leave the other behind."""
    from agentsec.ci.library import _CHECKOUT_USES
    raw = (get_component("self-audit").dir / _TEMPLATE).read_text(encoding="utf-8")
    assert f"uses: {_CHECKOUT_USES}" in raw


@pytest.mark.parametrize("secret", ["", "AGENTSEC_PAT"])
def test_rendered_self_audit_trips_none_of_agentsecs_own_guards(tmp_path: Path, secret: str) -> None:
    """The workflow `ci add` writes must pass the audit it runs. A tag-pinned `uses:` (the shape
    first planned) fails agentsec's own actions-sha-pin guard HIGH, i.e. its own gate; the control
    proves this test can see that, and that an unresolved pin could never pass quietly either."""
    from agentsec.audit import audit
    from agentsec.ci.library import UNRESOLVED_ACTION_SHA

    def workflow_rules(text: str) -> set[str]:
        root = tmp_path / str(len(list(tmp_path.iterdir())))
        (root / ".github" / "workflows").mkdir(parents=True)
        (root / ".github" / "workflows" / "agentsec-audit.yml").write_text(text, encoding="utf-8")
        res = audit(root, run_scanners=False, exceptions_path=Path(os.devnull))
        return {f.rule for f in res.findings if f.location.startswith(".github/workflows/agentsec-audit.yml")}

    rendered = _render_self_audit(install_secret=secret)
    assert workflow_rules(rendered) == set()
    if not secret:
        tag_pinned = rendered.replace(f"@{_SHA}", f"@v{__version__}")
        assert "actions-sha-pin/unpinned-action" in workflow_rules(tag_pinned)
        unresolved = _render_self_audit(action_sha="")
        assert f"@{UNRESOLVED_ACTION_SHA}" in unresolved
        assert "actions-sha-pin/unpinned-action" in workflow_rules(unresolved)


@pytest.mark.skipif(shutil.which("sh") is None, reason="needs a POSIX sh")
@pytest.mark.parametrize("existing", [None, "node_modules/", ".env\n"])
def test_the_ignore_step_keeps_the_agentsec_checkout_out_of_detection(
    tmp_path: Path, existing: str | None,
) -> None:
    """Run the rendered ignore step for real: before it, agentsec's own source in the nested
    checkout changes the detected stack (its `.git` is a directory, so the walk enters it);
    after it, the checkout is invisible and the repo's own `.gitignore` lines survive."""
    step = next(s for s in _self_audit_steps(_render_self_audit(install_secret="AGENTSEC_PAT"))
                if s.get("name") == "Ignore the agentsec checkout in this run")
    (tmp_path / "README.md").write_text("plain repo\n", encoding="utf-8")
    nested = tmp_path / ".agentsec-action"
    (nested / ".git").mkdir(parents=True)
    (nested / "app.py").write_text("from fastapi import FastAPI\napp = FastAPI()\n", encoding="utf-8")
    if existing is not None:
        (tmp_path / ".gitignore").write_text(existing, encoding="utf-8")
    assert "fastapi" in detect(tmp_path).features  # the hazard the step exists for
    sh = shutil.which("sh")
    assert sh is not None
    subprocess.run([sh, "-ec", step["run"]], cwd=tmp_path, check=True)
    assert "fastapi" not in detect(tmp_path).features
    lines = (tmp_path / ".gitignore").read_text(encoding="utf-8").splitlines()
    assert "/.agentsec-action/" in lines
    if existing is not None:
        assert existing.strip() in lines


# --- the action pin: resolve_action_sha / install() ---------------------------

_TAG_OBJ, _COMMIT = "1" * 40, "2" * 40


class _FakeGit:
    """Stands in for `subprocess.run` inside library.resolve_action_sha."""

    def __init__(self, stdout: str = "", returncode: int = 0, stderr: str = "",
                 raises: BaseException | None = None) -> None:
        self.stdout, self.returncode, self.stderr, self.raises = stdout, returncode, stderr, raises
        self.calls: list[tuple[list[str], dict[str, str]]] = []

    def __call__(self, argv: list[str], **kw: Any) -> subprocess.CompletedProcess[str]:
        self.calls.append((argv, kw["env"]))
        if self.raises is not None:
            raise self.raises
        return subprocess.CompletedProcess(argv, self.returncode, self.stdout, self.stderr)


@pytest.mark.parametrize(("stdout", "want"), [
    # an annotated (signed) release tag: only the peeled line names the commit
    (f"{_TAG_OBJ}\trefs/tags/v1.2.3\n{_COMMIT}\trefs/tags/v1.2.3^{{}}\n", _COMMIT),
    # a lightweight tag has no peeled line; its own line is the commit
    (f"{_COMMIT}\trefs/tags/v1.2.3\n", _COMMIT),
])
def test_resolve_action_sha_pins_the_commit_not_the_tag_object(
    monkeypatch: pytest.MonkeyPatch, stdout: str, want: str,
) -> None:
    from agentsec.ci import library
    fake = _FakeGit(stdout)
    monkeypatch.setattr(library.subprocess, "run", fake)
    assert library.resolve_action_sha("v1.2.3", "https://example.test/o/agentsec") == want
    ((argv, env),) = fake.calls
    assert argv == ["git", "ls-remote", "https://example.test/o/agentsec",
                    "refs/tags/v1.2.3", "refs/tags/v1.2.3^{}"]
    assert env["GIT_TERMINAL_PROMPT"] == "0"  # a private repo fails fast, never prompts


@pytest.mark.parametrize(("fake", "message"), [
    (_FakeGit(""), "has no release tag v1.2.3"),       # ls-remote exits 0 for a missing tag
    (_FakeGit("deadbeef\trefs/tags/v1.2.3\n"), "has no release tag v1.2.3"),
    (_FakeGit(returncode=128, stderr="fatal: could not read Username for 'https://github.com'\n"),
     "could not read Username"),
    (_FakeGit(raises=FileNotFoundError("git")), "could not run `git ls-remote"),
    (_FakeGit(raises=subprocess.TimeoutExpired(["git"], 30)), "could not run `git ls-remote"),
])
def test_resolve_action_sha_fails_loudly_and_names_the_escape_hatch(
    monkeypatch: pytest.MonkeyPatch, fake: _FakeGit, message: str,
) -> None:
    from agentsec.ci import library
    monkeypatch.setattr(library.subprocess, "run", fake)
    with pytest.raises(library.ActionPinError) as e:
        library.resolve_action_sha("v1.2.3")
    assert message in str(e.value) and "--action-sha" in str(e.value)


def test_only_self_audit_needs_the_action_pin() -> None:
    from agentsec.ci.library import needs_action_sha
    assert {c.id for c in load_components() if needs_action_sha(c)} == {"self-audit"}


def test_install_needs_a_pin_to_write_self_audit_and_never_looks_one_up(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The library makes no network call: the CLI resolves the pin under the egress policy. A
    write without a pin refuses BEFORE anything is written; a dry run and other components need
    none; a given pin is rendered as is."""
    from agentsec.ci import library

    def boom(tag: str) -> str:
        raise AssertionError("install() must never look the pin up itself")

    monkeypatch.setattr(library, "resolve_action_sha", boom)
    c, prof = get_component("self-audit"), detect(_FIXTURE)
    with pytest.raises(library.ActionPinError, match="pass action_sha"):
        install(c, prof, tmp_path / "none")
    assert not (tmp_path / "none").exists()
    assert all(r.action == "would-write" for r in install(c, prof, tmp_path / "dry", dry_run=True))
    install(get_component("secret-scan"), prof, tmp_path / "other")
    install(c, prof, tmp_path / "given", action_sha=_SHA)
    given = (tmp_path / "given" / ".github" / "workflows" / "agentsec-audit.yml").read_text(encoding="utf-8")
    assert f"ai-agent-security@{_SHA}" in given


# --- private-repo install via token secret (F4) ----------------------------

def test_public_install_mentions_no_secret() -> None:
    from agentsec.ci.library import agentsec_install, agentsec_install_step
    assert agentsec_install("") == f"git+https://github.com/Zard-Lab/ai-agent-security@v{__version__}"
    step = agentsec_install_step("")
    assert "secrets." not in step and "GIT_ASKPASS" not in step and "x-access-token" not in step
    out = _render_python_sec()
    assert "secrets." not in out and "GIT_ASKPASS" not in out


def test_private_install_url_is_token_free() -> None:
    from agentsec.ci.library import agentsec_install
    priv = agentsec_install("AGENTSEC_PAT")
    assert priv == f"git+https://x-access-token@github.com/Zard-Lab/ai-agent-security@v{__version__}"
    assert "secrets." not in priv and "${" not in priv


_PRIVATE_STEP_NAME = "Install agentsec (private repo, token-free URL)"


def _render_python_sec(*, install_secret: str = "") -> str:
    """A component that still installs agentsec with pip (self-audit runs the action instead)."""
    c = get_component("python-sec")
    params = derive_params(c, detect(_FIXTURE), install_secret=install_secret)
    return render(next((c.dir / "files").rglob("*.tmpl")).read_text(encoding="utf-8"), params)


def test_private_install_renders_into_workflow() -> None:
    """The PAT reaches the step only through `env:` and git only through GIT_ASKPASS; no URL and
    no command line carries it, and the rendered YAML parses."""
    out = _render_python_sec(install_secret="AGENTSEC_PAT")
    doc = yaml.safe_load(out)
    step = next(s for s in doc["jobs"]["python-security"]["steps"] if s.get("name") == _PRIVATE_STEP_NAME)
    assert step["env"] == {"AGENTSEC_PAT": "${{ secrets.AGENTSEC_PAT }}"}
    run = step["run"]
    assert "secrets." not in run, "the secret expression must not appear in the shell"
    assert f'pip install "git+https://x-access-token@github.com/Zard-Lab/ai-agent-security@v{__version__}"' in run
    assert 'GIT_ASKPASS="$ASKPASS" GIT_TERMINAL_PROMPT=0 \\' in run
    assert 'mktemp "${RUNNER_TEMP:-/tmp}/agentsec-askpass.XXXXXX"' in run
    assert "trap 'rm -f \"$ASKPASS\"' EXIT" in run
    # The printf keeps its literal `\n` escapes and `%%` (the outer printf expands them).
    assert r"""printf '#!/bin/sh\nexec printf %%s "$AGENTSEC_PAT"\n' > """ + '"$ASKPASS"' in run
    for ln in out.splitlines():  # the secret expression appears exactly once: the env mapping
        if "secrets.AGENTSEC_PAT" in ln:
            assert ln.strip() == "AGENTSEC_PAT: ${{ secrets.AGENTSEC_PAT }}", ln


@pytest.mark.parametrize("cid", ["dast", "db-lint", "garak", "promptfoo", "python-sec"])
def test_every_private_install_is_token_free(cid: str) -> None:
    c = get_component(cid)
    params = derive_params(c, detect(_FIXTURE), install_secret="MY_PAT")
    out = render(next((c.dir / "files").rglob("*.tmpl")).read_text(encoding="utf-8"), params)
    yaml.safe_load(out)
    assert "x-access-token@github.com" in out and "GIT_ASKPASS" in out
    assert not re.search(r"https://[^/\s\"']*\$\{\{", out), "a secret expression is inside a URL"


@pytest.mark.skipif(shutil.which("sh") is None, reason="needs a POSIX sh")
def test_rendered_askpass_script_answers_with_the_token(tmp_path: Path) -> None:
    """Run the rendered printf line for real: the askpass file it writes must print the token
    from the environment (and nothing else), which is what git reads as the password."""
    run = next(
        s for s in yaml.safe_load(_render_python_sec(install_secret="AGENTSEC_PAT"))["jobs"]["python-security"]["steps"]
        if s.get("name") == _PRIVATE_STEP_NAME
    )["run"]
    printf_line = next(ln.strip() for ln in run.splitlines() if ln.strip().startswith("printf "))
    sh = shutil.which("sh")
    assert sh is not None
    base_env = {k: v for k, v in os.environ.items() if k != "AGENTSEC_PAT"}
    subprocess.run([sh, "-c", printf_line], cwd=tmp_path, env={**base_env, "ASKPASS": "askpass.sh"},
                   check=True)
    script = (tmp_path / "askpass.sh").read_text(encoding="utf-8")
    assert script == '#!/bin/sh\nexec printf %s "$AGENTSEC_PAT"\n'  # no secret in the file
    res = subprocess.run([sh, "askpass.sh"], cwd=tmp_path, env={**base_env, "AGENTSEC_PAT": "tok-123"},
                         capture_output=True, text=True, encoding="utf-8", check=True)
    assert res.stdout == "tok-123"


# --- round-1 review of #1173: L5 (quoting, and inputs the pinned action declares) ------------

@pytest.mark.parametrize("path", ["o'brien: #mod", "a'b'c", "mod #1"])
def test_an_audit_path_with_yaml_specials_round_trips(path: str) -> None:
    """R1 L5: `'`, `: ` and ` #` in --path used to end the single-quoted scalar early (invalid
    YAML, or a silently different path). Every place the path lands parses back to it exactly."""
    out = _render_self_audit(audit_path=path, with_baseline=True)
    doc = yaml.safe_load(out)
    step = _action_step(out)
    assert step["with"]["path"] == path
    assert step["with"]["baseline-snapshot"] == f"{path}/agentsec-baseline.json"
    on = doc[True] if True in doc else doc["on"]  # PyYAML reads the `on:` key as True
    assert on["pull_request"]["paths"] == [f"{path}/**"] and on["push"]["paths"] == [f"{path}/**"]


def test_the_self_audit_passes_only_inputs_the_same_versions_action_declares() -> None:
    """R1 L5: the template pins the action of its own release, so every `with:` key it renders
    must be an input that release's action.yml declares (GitHub only warns on an unknown input,
    and the feature behind it would be silently missing)."""
    action = yaml.safe_load((Path(__file__).resolve().parents[1] / "action.yml").read_text(encoding="utf-8"))
    rendered = _action_step(_render_self_audit(with_baseline=True))["with"]
    assert set(rendered) <= set(action["inputs"]), sorted(set(rendered) - set(action["inputs"]))
