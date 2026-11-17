"""CI component library: discover manifests, adapt to a stack, install files.

A component lives under `components/<id>/` with a `component.json` manifest and a
`files/` tree. Manifests are JSON (parsed with stdlib `json`) so the runtime
stays dependency-free — `pyyaml` is a dev-only dep. Templated files end in
`.tmpl` and are rendered with the `@@TOKEN@@` engine in `render.py`; everything
else is copied verbatim. Token substitution also runs over destination *paths*,
so a file stored at `files/@@FRONTEND_DIR@@/react-doctor.config.json` lands in
the repo's actual detected frontend dir.
"""
from __future__ import annotations

import json
import os
import re
import subprocess  # nosec B404 (one fixed `git ls-remote` argv, no shell)
from dataclasses import dataclass, field
from pathlib import Path

from agentsec import AGENTSEC_REPO_SLUG, AGENTSEC_REPO_URL, __version__, pins
from agentsec.ci.render import render
from agentsec.detect import StackProfile

COMPONENTS_DIR = Path(__file__).parent / "components"

# Verified commit-SHA pins (kept here only for reference; the values live in the
# template files / setup blocks). Pinning third-party actions to a commit SHA is
# a hardening lesson we preserve from the production CI.
_PM_DLX = {"pnpm": "pnpm dlx", "bun": "bunx", "npm": "npx"}
_PM_EXEC = {"pnpm": "pnpm exec", "bun": "bunx", "npm": "npx"}  # run a project-local binary
_PM_INSTALL = {
    "pnpm": "pnpm install --frozen-lockfile",
    "bun": "bun install",
    "npm": "npm install",
}
_PM_PRECEDENCE = ("pnpm", "bun", "npm")

# Native-tool pins for the rendered CI workflows. The single source is `pins.py`;
# the CI workflows always run on the linux/x86_64 runner, so `ci_sha256()` returns
# that platform's checksum (the value backing the @@GITLEAKS_SHA256@@ token).
_GITLEAKS_VERSION = pins.version("gitleaks")
_GITLEAKS_SHA256 = pins.ci_sha256("gitleaks")

# Where rendered CI workflows install agentsec from (until it's on PyPI). The repo
# identity is the canonical constant in `agentsec/__init__.py` (the one place to flip
# on an org move / PyPI release); it is surfaced to every template as the
# `@@AGENTSEC_INSTALL_STEP@@` block token, so every component picks up a change
# automatically. The ref is the release tag of the agentsec that RENDERED the workflow
# (`_agentsec_ref()`), never a moving branch: a security gate must not install whatever
# `main` happens to be on the day the job runs.
_AGENTSEC_REPO = AGENTSEC_REPO_URL
# The non-secret username GitHub accepts for token auth. The private install puts only this
# literal in the URL; the token itself reaches git through GIT_ASKPASS at fetch time.
_TOKEN_USER = "x-access-token"  # nosec B105 (GitHub's documented public username, not a secret)


def _agentsec_ref() -> str:
    """The git ref a rendered workflow installs agentsec from: `v<__version__>`.

    Every release carries a signed `vX.Y.Z` tag (release-tag-guard.yml), so this pins the
    rendered workflow to the exact version of agentsec that rendered it. Two edges, both
    accepted on purpose and with no network call: a dev checkout whose checklist version is
    bumped but not yet released renders a tag the next release creates; and an unreadable
    checklist (`__version__ == "0+unknown"`) has no version to pin, so it falls back to
    `main` (which `ci doctor` then flags as an unpinned install).
    """
    if __version__ == "0+unknown":
        return "main"
    return f"v{__version__}"


# The self-audit workflow runs agentsec's composite action (`action.yml` at the agentsec repo
# root) instead of installing it. A `uses:` must name a full commit SHA: agentsec's own
# `actions-sha-pin` guard fires HIGH on a tag, so a tag-pinned render would fail its own gate.
# The installed package cannot know its release commit offline (the signed tag is created on
# the release commit after the package is built), so `ci add` resolves `v<version>` to its
# commit SHA once, with `git ls-remote`, through the user's own git credentials. That lookup is
# the only network call here, and only the CLI makes it (disclosed, refused under
# DO_NOT_TRACK=1); `derive_params` and `install` never touch the network.
_SHA40 = re.compile(r"[0-9a-f]{40}")
# The private variant checks agentsec out inside the workspace (a local `uses:` is the only way
# to run a private action owned by another account). Not `.agentsec/`: that is agentsec's own
# per-repo config directory (`agentsec.config._CONFIG_REL`).
ACTION_CHECKOUT_DIR = ".agentsec-action"
# The same checkout pin the self-audit template uses for the repo itself (a test keeps the two
# equal, since only the template is visible to a reader of the rendered workflow).
_CHECKOUT_USES = "actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd  # v6.0.2"
# What `derive_params` renders when no SHA was resolved. Never written by `install()`, which
# resolves first; not 40-hex, so `actions-sha-pin` and `ci doctor` both flag it if it ever is.
UNRESOLVED_ACTION_SHA = "UNRESOLVED-run-agentsec-ci-add"
_ACTION_USES_MARKER = "@@AGENTSEC_ACTION_USES@@"


class ActionPinError(RuntimeError):
    """The release tag could not be resolved to a commit SHA (offline, no access, no such tag)."""


def resolve_action_sha(tag: str, repo_url: str = AGENTSEC_REPO_URL, *, timeout: float = 30.0) -> str:
    """The commit SHA the agentsec release tag `tag` points at, read with `git ls-remote`.

    Asks for both `refs/tags/<tag>` and its peeled form `refs/tags/<tag>^{}`: a release tag is
    annotated (signed), so the plain line names the TAG object and only the peeled line names
    the commit a `uses:` must pin (a lightweight tag has no peeled line, and its plain line is
    the commit). `git ls-remote` exits 0 with no output for a missing tag, so an empty answer is
    an error here, never a silent fallback. `GIT_TERMINAL_PROMPT=0` makes a private repo the
    user cannot reach fail at once instead of waiting on a password prompt.
    """
    fix = "pass `--action-sha <40-hex commit SHA of that release>` to skip the lookup"
    try:
        proc = subprocess.run(  # nosec B603 B607 (fixed argv; the URL and tag are not user shell input)
            ["git", "ls-remote", repo_url, f"refs/tags/{tag}", f"refs/tags/{tag}^{{}}"],
            capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=timeout,
            env={**os.environ, "GIT_TERMINAL_PROMPT": "0"}, check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as e:
        raise ActionPinError(f"could not run `git ls-remote {repo_url}` ({e}); {fix}") from e
    if proc.returncode != 0:
        detail = (proc.stderr.strip().splitlines() or ["no output"])[-1]
        raise ActionPinError(
            f"`git ls-remote {repo_url}` failed: {detail}. If the agentsec repo is private, the git "
            f"on this machine needs HTTPS read access to it (e.g. `gh auth setup-git`); or {fix}"
        )
    refs = {
        parts[1]: parts[0] for parts in (ln.split() for ln in proc.stdout.splitlines()) if len(parts) == 2
    }
    sha = refs.get(f"refs/tags/{tag}^{{}}") or refs.get(f"refs/tags/{tag}", "")
    if not _SHA40.fullmatch(sha):
        raise ActionPinError(
            f"{repo_url} has no release tag {tag} (this agentsec's version is not released yet, "
            f"so there is no release commit to pin); {fix}"
        )
    return sha


def needs_action_sha(component: Component) -> bool:
    """True when a template of `component` pins agentsec's action (today: `self-audit` only)."""
    fdir = component.dir / "files"
    return fdir.is_dir() and any(
        _ACTION_USES_MARKER in src.read_text(encoding="utf-8")
        for src in fdir.rglob("*.tmpl")
    )


def agentsec_action_uses(action_sha: str, install_secret: str = "") -> str:  # nosec B107
    """The `uses:` value of the self-audit step (the `@@AGENTSEC_ACTION_USES@@` token).

    Public: the remote action pinned to `action_sha`, with the release tag as the trailing
    comment Dependabot and Renovate read to bump it. Private: the local checkout
    (`agentsec_action_setup` puts it there), since a remote `uses:` cannot read a private
    action owned by another account.
    """
    if install_secret:
        return f"./{ACTION_CHECKOUT_DIR}"
    return f"{AGENTSEC_REPO_SLUG}@{action_sha}  # {_agentsec_ref()}"


def agentsec_action_setup(action_sha: str, install_secret: str = "") -> str:  # nosec B107
    """The steps that put a private agentsec action in reach (the `@@AGENTSEC_ACTION_SETUP@@` token).

    Empty for the public form. Private (`install_secret` = the GitHub secret name): check the
    agentsec repo out at `action_sha` into `ACTION_CHECKOUT_DIR` with the token and
    `persist-credentials: false` (the token is not left in that checkout's git config), then
    ignore that directory for this run. The scan walks a nested checkout (its `.git` is a
    directory, not a worktree link), so without the ignore line agentsec's own source and
    deliberately vulnerable fixtures would change the stack the scan detects; the action drops
    their findings either way. The line is appended on the runner only and never committed.
    Pre-indented for a 4-space step list, like `_pm_setup_block`; it opens with a blank line
    and ends with a newline, so the template places the token alone on a line at column 0.
    """
    if not install_secret:
        return ""
    secret_expr = "${{ secrets." + install_secret + " }}"
    return (
        "\n"
        "    # The agentsec repo is private: check its action out with a read-only token, then\n"
        "    # run it as a local action. The token is not persisted in the checkout.\n"
        "    - name: Check out the agentsec action (private repo)\n"
        f"      uses: {_CHECKOUT_USES}\n"
        "      with:\n"
        f"        repository: {AGENTSEC_REPO_SLUG}\n"
        f"        ref: {action_sha}  # {_agentsec_ref()}\n"
        f"        token: {secret_expr}\n"
        f"        path: {ACTION_CHECKOUT_DIR}\n"
        "        persist-credentials: false\n"
        "\n"
        "    # Keep that checkout out of the scan (it is inside the workspace). Runner only.\n"
        "    - name: Ignore the agentsec checkout in this run\n"
        f"      run: printf '\\n/{ACTION_CHECKOUT_DIR}/\\n' >> .gitignore\n"
    )


@dataclass
class Component:
    id: str
    title: str
    summary: str
    category: str
    applies_when: list[str] = field(default_factory=list)
    requires_secrets: list[str] = field(default_factory=list)
    params: dict[str, dict[str, str]] = field(default_factory=dict)
    depends_on: list[str] = field(default_factory=list)
    notes: str = ""
    dir: Path = COMPONENTS_DIR

    def applies(self, profile: StackProfile) -> bool:
        return set(self.applies_when).issubset(profile.features)


@dataclass
class InstalledFile:
    target: Path           # absolute path under dest_root
    action: str            # "write" | "would-write" | "skip-exists"


# ---------------------------------------------------------------------------
# Discovery
# ---------------------------------------------------------------------------

def load_components() -> list[Component]:
    """Load every component manifest under COMPONENTS_DIR, sorted by id."""
    out: list[Component] = []
    for manifest in sorted(COMPONENTS_DIR.glob("*/component.json")):
        data = json.loads(manifest.read_text(encoding="utf-8"))
        out.append(
            Component(
                id=data["id"],
                title=data.get("title", data["id"]),
                summary=data.get("summary", ""),
                category=data.get("category", ""),
                applies_when=list(data.get("applies_when", [])),
                requires_secrets=list(data.get("requires_secrets", [])),
                params=dict(data.get("params", {})),
                depends_on=list(data.get("depends_on", [])),
                notes=data.get("notes", ""),
                dir=manifest.parent,
            )
        )
    return sorted(out, key=lambda c: c.id)


def get_component(cid: str) -> Component:
    for c in load_components():
        if c.id == cid:
            return c
    available = ", ".join(c.id for c in load_components())
    raise ValueError(f"unknown component '{cid}'. Available: {available}")


# ---------------------------------------------------------------------------
# Adaptation
# ---------------------------------------------------------------------------

def _python_dirs(profile: StackProfile) -> str:
    dirs = [d for d in profile.python_dirs if d != "."]
    return " ".join(dirs) if dirs else "."


def _pick_pm(profile: StackProfile) -> str:
    for pm in _PM_PRECEDENCE:
        if pm in profile.package_managers:
            return pm
    return "npm"


def _pm_setup_block(pm: str, frontend_dir: str, node_version: str) -> str:
    """A pre-indented (4-space, step-level) YAML snippet that sets up the JS
    toolchain for `pm`. All tokens are resolved here so the returned string is
    plain text (render() is single-pass and won't re-process injected tokens).
    Caching is intentionally omitted so the workflow runs even before a lockfile
    is committed; enable `cache:` on setup-node once you commit one."""
    node = (
        "    - name: Set up Node.js\n"
        "      uses: actions/setup-node@48b55a011bda9f5d6aeb4c2d9c7362e8dae4041e  # v6.4.0\n"
        "      with:\n"
        f"        node-version: '{node_version}'"
    )
    if pm == "pnpm":
        return (
            "    - name: Install pnpm\n"
            "      uses: pnpm/action-setup@fc06bc1257f339d1d5d8b3a19a8cae5388b55320  # v5.0.0\n"
            "      with:\n"
            f"        package_json_file: {frontend_dir}/package.json\n"
            "        run_install: false\n"
            "\n"
            f"{node}"
        )
    if pm == "bun":
        return (
            "    - name: Set up Bun\n"
            "      uses: oven-sh/setup-bun@0c5077e51419868618aeaa5fe8019c62421857d6  # v2.2.0\n"
            "\n"
            f"{node}"
        )
    return node  # npm: Node alone is enough


def _yaml_sq(text: str) -> str:
    """`text` escaped for the inside of a YAML single-quoted scalar (`'` is written `''`)."""
    return text.replace("'", "''")


def baseline_rel(audit_path: str) -> str:
    """Repo-relative path of the self-audit baseline for a given audit scope."""
    return "agentsec-baseline.json" if audit_path == "." else f"{audit_path}/agentsec-baseline.json"


def agentsec_install(install_secret: str = "") -> str:  # nosec B107 ("" is a not-provided sentinel)
    """The `pip install` source for agentsec in a rendered workflow. Always token-free.

    Default: the public `git+https://github.com/<slug>@v<version>` URL. When
    `install_secret` is given (the repo is private and the runner's GITHUB_TOKEN can't
    reach it), the URL carries only the non-secret username `x-access-token@`; the token
    is supplied by `agentsec_install_step()` through GIT_ASKPASS, never in the URL. A
    token in the URL lands in pip's git cache and in the process args, both readable by
    later jobs on a persistent (self-hosted) runner.
    """
    base = f"git+{_AGENTSEC_REPO}@{_agentsec_ref()}"
    if not install_secret:
        return base
    return base.replace("https://", f"https://{_TOKEN_USER}@", 1)


# The private-install shell, mirrored from the production-proven HWH `install-agentsec`
# composite action. The askpass script holds no secret (it echoes an env var), lives under
# $RUNNER_TEMP and is deleted on exit; GIT_TERMINAL_PROMPT=0 fails loudly instead of hanging
# when the token is missing or dead. `\\n` below is a literal backslash-n in the rendered YAML:
# the outer printf turns it into a newline and `%%` into `%`, so the askpass file reads
# `#!/bin/sh` then `exec printf %s "$AGENTSEC_PAT"`.
_ASKPASS_RUN = (
    "        set -euo pipefail\n"
    '        ASKPASS="$(mktemp "${RUNNER_TEMP:-/tmp}/agentsec-askpass.XXXXXX")"\n'
    "        printf '#!/bin/sh\\nexec printf %%s \"$AGENTSEC_PAT\"\\n' > \"$ASKPASS\"\n"
    '        chmod +x "$ASKPASS"\n'
    "        trap 'rm -f \"$ASKPASS\"' EXIT\n"
    '        GIT_ASKPASS="$ASKPASS" GIT_TERMINAL_PROMPT=0 \\\n'
)


def agentsec_install_step(install_secret: str = "") -> str:  # nosec B107 ("" is a not-provided sentinel)
    """The whole `Install agentsec` workflow step (the `@@AGENTSEC_INSTALL_STEP@@` block token).

    Pre-indented for a 4-space step list (`    - name:`), like `_pm_setup_block`, with no
    trailing newline: a template places the token alone on a line at column 0. Public: one
    `pip install` of the release-tagged URL. Private (`install_secret` = the GitHub secret
    name): the token-free `x-access-token@` URL, with the secret mapped into the step's
    `env:` and handed to git only through GIT_ASKPASS.
    """
    url = agentsec_install(install_secret)
    if not install_secret:
        return (
            "    - name: Install agentsec\n"
            f'      run: pip install "{url}"'
        )
    secret_expr = "${{ secrets." + install_secret + " }}"
    return (
        "    # Token-free private install: the URL carries only the literal username\n"
        "    # x-access-token; the PAT reaches git through GIT_ASKPASS at fetch time.\n"
        "    - name: Install agentsec (private repo, token-free URL)\n"
        "      env:\n"
        f"        AGENTSEC_PAT: {secret_expr}\n"
        "      run: |\n"
        f"{_ASKPASS_RUN}"
        f'          pip install "{url}"'
    )


def derive_params(
    component: Component, profile: StackProfile,
    *, audit_path: str = ".", with_baseline: bool = False, install_secret: str = "",
    advisory: bool = False, action_sha: str = "",
) -> dict[str, str]:
    """Resolve every template token for `component` against the detected stack.

    Returns a superset of tokens (render() ignores extras, errors on missing),
    so the same map serves any template. `RUNNER` is always `ubuntu-latest`. Pure: no
    network. `action_sha` is the resolved commit SHA of the release (see
    `resolve_action_sha`); left empty, the self-audit renders `UNRESOLVED_ACTION_SHA`.

    `audit_path` scopes the self-audit workflow to a subdir (monorepo module):
    it drives the action's `path:` (`@@AUDIT_PATH@@`) and the `@@SCOPE_PATHS@@` trigger
    filter. `with_baseline` adds the action's `baseline-snapshot:` (`@@BASELINE_WITH@@`) —
    the ratchet gate (findings stay visible; only NEW ones fail), not exception suppression.
    `advisory` (or a manifest `ADVISORY` default of "true") renders the action's
    `mode: advisory` (`@@AUDIT_MODE@@`): the report and SARIF are produced, the build never
    fails on findings.
    """
    params: dict[str, str] = {}

    # 1. manifest-declared params (resolve `from`, else `default`)
    for name, spec in component.params.items():
        src = spec.get("from")
        val: str | None = None
        if src == "profile.frontend_dir":
            val = profile.frontend_dir
        elif src == "profile.sql_dir":
            val = profile.sql_dir
        elif src == "profile.python_dirs":
            val = _python_dirs(profile)
        if not val:
            val = spec.get("default", "")
        params[name] = str(val)

    # 2. always-present globals (fill any the manifest didn't set)
    fe = params.get("FRONTEND_DIR") or profile.frontend_dir or "frontend"
    node = params.get("NODE_VERSION") or "22"
    params["FRONTEND_DIR"] = fe
    params["NODE_VERSION"] = node
    params["RUNNER"] = "ubuntu-latest"  # never self-hosted
    params.setdefault("PYTHON_VERSION", "3.12")
    params.setdefault("FAIL_ON", "high")
    params.setdefault("MIN_SCORE", "75")
    params.setdefault("REACT_DOCTOR_VERSION", pins.version("react-doctor"))
    params.setdefault("GITLEAKS_VERSION", _GITLEAKS_VERSION)
    params.setdefault("GITLEAKS_SHA256", _GITLEAKS_SHA256)
    params.setdefault("PYTHON_DIRS", _python_dirs(profile))
    params.setdefault("SQL_DIR", profile.sql_dir or "sql")
    params.setdefault("AGENTSEC_INSTALL_STEP", agentsec_install_step(install_secret))
    params.setdefault("TOP", "50")

    # self-audit advisory mode: report every finding, never fail the build (rollout).
    if advisory:
        params["ADVISORY"] = "true"
    params.setdefault("ADVISORY", "false")
    params["AUDIT_MODE"] = "advisory" if params["ADVISORY"] == "true" else "gate"

    # self-audit: agentsec's action, pinned to the release commit (or checked out, if private)
    sha = action_sha or UNRESOLVED_ACTION_SHA
    params["AGENTSEC_ACTION_USES"] = agentsec_action_uses(sha, install_secret)
    params["AGENTSEC_ACTION_SETUP"] = agentsec_action_setup(sha, install_secret)

    # self-audit scoping (monorepo subdir) + baseline rollout. The path lands in YAML
    # single-quoted scalars (`'...'`, where `''` is a literal `'`), so a `'`, `:` or `#` in it
    # cannot end the scalar early; the CLI refuses control characters, which no quoting carries.
    params["AUDIT_PATH"] = audit_path
    params["AUDIT_PATH_SQ"] = _yaml_sq(audit_path)
    params["SCOPE_PATHS"] = "" if audit_path == "." else f"\n    paths: ['{_yaml_sq(audit_path)}/**']"
    params["BASELINE_WITH"] = (
        f"\n        baseline-snapshot: '{_yaml_sq(baseline_rel(audit_path))}'" if with_baseline else ""
    )

    # 3. package-manager tokens
    pm = _pick_pm(profile)
    params["PM"] = pm
    params["PM_DLX"] = _PM_DLX[pm]
    params["PM_EXEC"] = _PM_EXEC[pm]
    params["PM_INSTALL"] = _PM_INSTALL[pm]
    params["PM_SETUP_BLOCK"] = _pm_setup_block(pm, fe, node)
    return params


# ---------------------------------------------------------------------------
# Files / install
# ---------------------------------------------------------------------------

def _files_dir(component: Component) -> Path:
    return component.dir / "files"


def _target_rel(rel: Path, params: dict[str, str] | None) -> Path:
    """Map a `files/`-relative source path to its target: strip a trailing
    `.tmpl` and (when params given) substitute `@@TOKEN@@` in path components."""
    s = str(rel)
    if s.endswith(".tmpl"):
        s = s[: -len(".tmpl")]
    if params is not None:
        s = render(s, params)
    return Path(s)


def would_write(
    component: Component, profile: StackProfile, dest_root: Path, *,
    force: bool = False, audit_path: str = ".",
) -> bool:
    """True when `install()` (not a dry run) would write at least one file: `force`, or any
    target that does not exist yet. Pure, so the CLI can ask before a network lookup."""
    if force:
        return True
    params = derive_params(component, profile, audit_path=audit_path)
    return any(not (dest_root / rel).exists() for rel in planned_files(component, params))


def planned_files(component: Component, params: dict[str, str] | None = None) -> list[Path]:
    """Repo-relative target paths the component would write (sorted)."""
    fdir = _files_dir(component)
    if not fdir.is_dir():
        return []
    out = [_target_rel(f.relative_to(fdir), params) for f in fdir.rglob("*") if f.is_file()]
    return sorted(out, key=str)


def install(
    component: Component,
    profile: StackProfile,
    dest_root: Path,
    *,
    force: bool = False,
    dry_run: bool = False,
    audit_path: str = ".",
    with_baseline: bool = False,
    install_secret: str = "",
    advisory: bool = False,
    action_sha: str = "",
) -> list[InstalledFile]:
    """Render + write the component's files under `dest_root`.

    Existing files are skipped unless `force`. With `dry_run`, nothing is
    written but the planned actions are returned. `audit_path` / `with_baseline`
    scope the self-audit workflow (monorepo subdir + baseline rollout).
    `install_secret` makes the workflow reach agentsec in a private repo via that GitHub
    secret (a pip install through GIT_ASKPASS, or for self-audit a token checkout of the
    action; never a token in a URL). `advisory` renders the self-audit in advisory mode.
    `action_sha` pins the self-audit's action. It is required only when such a component would
    write a file (`ActionPinError` otherwise, before anything is written): this module makes no
    network call, so the caller resolves it with `resolve_action_sha` (the CLI does, under the
    egress policy, and only when `would_write` says so). A dry run, or a run where every file
    already exists and `force` is off, writes nothing and needs none.
    """
    if (not action_sha and not dry_run and needs_action_sha(component)
            and would_write(component, profile, dest_root, force=force, audit_path=audit_path)):
        raise ActionPinError(
            f"'{component.id}' pins agentsec's action to a commit: pass action_sha "
            "(resolve it with resolve_action_sha)"
        )
    params = derive_params(
        component, profile, audit_path=audit_path, with_baseline=with_baseline,
        install_secret=install_secret, advisory=advisory, action_sha=action_sha,
    )
    fdir = _files_dir(component)
    results: list[InstalledFile] = []
    for src in sorted(fdir.rglob("*"), key=str):
        if not src.is_file():
            continue
        rel = src.relative_to(fdir)
        is_tmpl = src.name.endswith(".tmpl")
        target = dest_root / _target_rel(rel, params)
        raw = src.read_text(encoding="utf-8")
        content = render(raw, params) if is_tmpl else raw

        if target.exists() and not force:
            results.append(InstalledFile(target=target, action="skip-exists"))
            continue
        if dry_run:
            results.append(InstalledFile(target=target, action="would-write"))
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
        results.append(InstalledFile(target=target, action="write"))
    return results
