"""`agentsec ci doctor` — static preflight for generated agentsec CI workflows.

Reads the workflow files as **text** (no YAML/runtime deps) and flags the things
that otherwise only surface by failing in CI — the exact walls hit on the first
real-world setup:

- a private-repo install with no token (`could not read Username`);
- an install from a moving branch (`@main`) instead of a release tag or commit SHA
  (`install-unpinned`), and a token rendered into the install URL, where it lands in
  pip's git cache and the process args (`install-token-in-url`);
- a gate that opportunistically runs live-advisory scanners (node-audit via the
  runner's npm, …) → non-reproducible findings that break a baseline;
- a `--baseline-snapshot` the gate references but that doesn't exist on disk, or one saved
  before #853 that cannot gate a superseded SQL finding coming back live;
- a SARIF→code-scanning upload that needs GitHub Advanced Security (private repos
  403);
- the same hazards for agentsec's GitHub Action (what `ci add self-audit` renders): a
  `uses:` or private checkout `ref:` that is not a commit SHA (`install-unpinned`), a private
  checkout with no token, `scanners: all` in a gate, and a `baseline-snapshot:` that does not
  exist; plus two `info` notes that never change the verdict (a remote `uses:` needs a public
  repo; a `with:` shape the reader cannot take apart was not checked).

Turns "push → fail → read logs → fix → re-push" into one local check.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from agentsec import AGENTSEC_REPO_SLUG
from agentsec.drift import legacy_schema_rows, load_snapshot


@dataclass
class Diagnosis:
    level: str       # "ok" | "info" | "warn" | "error" (only warn and error count in the verdict)
    workflow: str
    title: str
    fix: str = ""
    check: str = ""  # stable id for the checks that have one (e.g. "install-unpinned")


# A GitHub expression (`${{ secrets.X }}`) contains spaces; collapse each to one placeholder
# so the URL patterns below can treat a URL as a single whitespace-free token.
_GH_EXPR = re.compile(r"\$\{\{.*?\}\}")
_EXPR_PLACEHOLDER = "$EXPR"
# The userinfo of a git+http(s) URL: everything between `://` and the first `@` that comes
# before any `/`. A URL with no userinfo (`git+https://github.com/o/r@main`) does not match,
# because the first `@` there is the ref, after the path's `/`.
_GIT_USERINFO = re.compile(r"git\+https?://(?P<userinfo>[^/\s\"'@]*)@")
# What makes a userinfo a credential: an expansion (`${{ secrets.X }}`, `$TOKEN`), a password
# (`user:secret`), or a literal GitHub token. The bare username `x-access-token` is none of
# these: it is the token-free form (the token reaches git through GIT_ASKPASS).
_CREDENTIAL = re.compile(r"\$|:|gh[pousr]_|github_pat_")
# A git install URL of agentsec itself (repo path names agentsec / its distribution), with its
# optional `@ref` (up to a quote, whitespace or a `#egg=`/`#subdirectory=` fragment).
_AGENTSEC_GIT_URL = re.compile(
    r"git\+(?:https?|ssh)://(?:[^/\s\"'@]*@)?[^/\s\"']+/[^\s\"'@#]*(?:agentsec|ai-agent-security)"
    r"[^\s\"'@#]*(?:@(?P<ref>[^\s\"'#]+))?"
)
# Refs that pin an immutable-by-convention version: a release tag or a full commit SHA.
_PINNED_REF = re.compile(r"v\d+\.\d+\.\d+(?:[-+.][0-9A-Za-z.+-]*)?|[0-9a-f]{40}")
_SHA40 = re.compile(r"[0-9a-f]{40}")
# agentsec's own repository NAME (the action is `action.yml` at that repo's root). Matched under
# any owner, so a fork is still checked, but never as a substring: `acme/agentsec-scan-action` and
# `acme/ai-agent-security-ci` are someone else's.
_AGENTSEC_REPO_NAME = AGENTSEC_REPO_SLUG.split("/", 1)[1].lower()
# A step key line: `- uses: x` / `uses: x` (the key column is where `uses` starts).
_USES_LINE = re.compile(r"^(?P<lead>\s*(?:-\s+)?)uses:\s*(?P<value>.*)$")
_KEY_LINE = re.compile(r"^(?P<indent>\s*)(?:-\s+)?(?P<key>[A-Za-z0-9_-]+):\s*(?P<value>.*)$")


@dataclass
class _ActionStep:
    """One workflow step that runs agentsec's action, or checks the agentsec repo out."""
    uses: str                 # the `uses:` value, comment and quotes stripped
    with_: dict[str, str]     # the step's `with:` scalars, comments and quotes stripped
    readable: bool = True     # False: a `with:` whose shape the text reader cannot take apart


def _scalar(value: str) -> str:
    """A YAML plain or quoted scalar as text. A quoted one is read to its closing quote first (a
    single-quoted scalar's `''` is one `'`), so a ` #` inside the quotes is content, and whatever
    follows the quote (a comment) is dropped; a plain one loses its trailing ` # comment`."""
    value = value.strip()
    if value[:1] == "'":
        out: list[str] = []
        i = 1
        while i < len(value):
            if value[i] == "'":
                if value[i + 1:i + 2] == "'":
                    out.append("'")
                    i += 2
                    continue
                return "".join(out)
            out.append(value[i])
            i += 1
        return value  # unterminated: leave it as written
    if value[:1] == '"':
        end = value.find('"', 1)
        return value[1:end] if end != -1 else value
    return re.sub(r"\s+#.*$", "", value).strip()


def _flow_mapping(value: str) -> dict[str, str] | None:
    """A one-line flow mapping (`{ a: 1, b: 'x' }`) as scalars, or None when it is not one this
    reader can split safely (a nested collection, or a comma or brace inside a quoted value)."""
    if not (value.startswith("{") and value.endswith("}")):
        return None
    inner = value[1:-1].strip()
    if not inner:
        return {}
    out: dict[str, str] = {}
    for part in inner.split(","):
        key, sep, val = part.partition(":")
        key, val = key.strip(), val.strip()
        if not sep or not key or any(ch in val for ch in "{}[]") or val.count("'") % 2 or val.count('"') % 2:
            return None
        out[_scalar(key)] = _scalar(val)
    return out


def _steps_using(text: str) -> list[_ActionStep]:
    """Every step in `text` with a `uses:` key, with that step's `with:` scalars.

    Text only, like every check here: a step's keys sit at the column `uses` starts at, the
    step's `- ` sits two columns left of that, and the step ends at the first non-blank line
    indented less than its keys. `with:` values are read at the first child column only, so the
    body of a block scalar (`exclude: |`) is never mistaken for a key. A one-line flow mapping
    (`with: { scanners: all }`) is read too; any other inline `with:` value (an alias, a nested
    flow collection) marks the step unreadable, so the caller says so instead of reporting a
    clean step it never saw.
    """
    lines = text.splitlines()
    out: list[_ActionStep] = []
    for i, raw in enumerate(lines):
        m = _USES_LINE.match(raw)
        if not m:
            continue
        key_col = len(m.group("lead"))
        start = i
        if "-" not in m.group("lead"):  # `uses:` is not the step's first key: find the `- `
            while start > 0:
                start -= 1
                prev = lines[start]
                if prev.strip() and len(prev) - len(prev.lstrip()) < key_col:
                    break
        end = i + 1
        while end < len(lines) and (
            not lines[end].strip() or lines[end].lstrip().startswith("#")
            or len(lines[end]) - len(lines[end].lstrip()) >= key_col
        ):
            end += 1
        with_: dict[str, str] = {}
        readable = True
        body = lines[start:end]
        for j, ln in enumerate(body):
            k = _KEY_LINE.match(ln)
            if not (k and k.group("key") == "with"):
                continue
            inline = re.sub(r"(?:^|\s+)#.*$", "", k.group("value")).strip()  # `with:  # note` is block style
            if inline:
                flow = _flow_mapping(inline)
                if flow is None:
                    readable = False
                else:
                    with_.update(flow)
                continue
            with_col, child_col = k.start("key"), -1
            for child in body[j + 1:]:
                if not child.strip() or child.lstrip().startswith("#"):
                    continue
                col = len(child) - len(child.lstrip())
                if col <= with_col:
                    break
                if child_col == -1:
                    child_col = col
                if col == child_col and (c := _KEY_LINE.match(child)):
                    with_[c.group("key")] = _scalar(c.group("value"))
        out.append(_ActionStep(_scalar(m.group("value")), with_, readable))
    return out


def _is_agentsec_repo(name: str) -> bool:
    """`owner/<agentsec's repo name>` exactly (any owner, so a fork counts; no sub-path)."""
    owner, sep, repo = name.strip().partition("/")
    return bool(owner and sep) and repo.lower().removesuffix(".git") == _AGENTSEC_REPO_NAME


def _local_path(path: str) -> str:
    return path.strip().removeprefix("./").rstrip("/")


def _is_agentsec_action(uses: str, local_dirs: set[str]) -> bool:
    """A `uses:` of agentsec's action. Remote: `owner/<agentsec repo>@ref` with nothing after the
    repo (a sub-path is another action or a reusable workflow, not this one). Local: a directory
    a step of this workflow checked agentsec's repo out to (`local_dirs`)."""
    if uses.startswith("./"):
        return _local_path(uses) in local_dirs
    target, sep, _ref = uses.partition("@")
    return bool(sep) and _is_agentsec_repo(target)


def _action_pin_diag(name: str, what: str, ref: str) -> Diagnosis | None:
    """`install-unpinned` for agentsec's action: a `uses:` or checkout `ref:` must be a full SHA.

    Stricter than a pip install's rule (where a release tag passes): agentsec's own
    `actions-sha-pin` guard fires HIGH on any `uses:` that is not a commit SHA, and a tag can
    be moved to new code after you reviewed it."""
    if ref and "$" in ref:
        return None  # an expression or variable ref: pinned or not upstream; can't tell here
    if ref and _SHA40.fullmatch(ref):
        return None
    shown = f"@{ref}" if ref else "no ref (the default branch)"
    return Diagnosis(
        "warn", name, f"agentsec's action {what} a moving ref: {shown}",
        "pin the 40-hex commit SHA of an agentsec release (a tag can be moved after you review "
        "it, and agentsec's own actions-sha-pin guard fails the gate on it); re-render with "
        "`agentsec ci add self-audit --force`, which resolves it",
        check="install-unpinned",
    )


def _normalize(ln: str) -> str:
    return _GH_EXPR.sub(_EXPR_PLACEHOLDER, ln)


def _token_in_url(ln: str) -> bool:
    """True when an agentsec git install URL on this line carries a credential in its userinfo.

    Only lines that install agentsec itself count: a token in some other repo's URL is not
    this check's business."""
    norm = _normalize(ln)
    if not _AGENTSEC_GIT_URL.search(norm):
        return False
    return any(_CREDENTIAL.search(m.group("userinfo")) for m in _GIT_USERINFO.finditer(norm))


def _install_ref_findings(name: str, ln: str) -> list[Diagnosis]:
    """`install-unpinned` + `install-token-in-url` for one (non-comment) workflow line."""
    out: list[Diagnosis] = []
    for m in _AGENTSEC_GIT_URL.finditer(_normalize(ln)):
        ref = m.group("ref")
        if ref and "$" in ref:
            continue  # a variable ref (`@${AGENTSEC_SHA}`) is pinned or not upstream; can't tell here
        if ref and _PINNED_REF.fullmatch(ref):
            continue
        shown = f"@{ref}" if ref else "no @ref (the default branch)"
        out.append(Diagnosis(
            "warn", name, f"agentsec installed from a moving ref: {shown}",
            "a security gate should install a fixed version: pin a release tag (`@vX.Y.Z`) or a "
            "40-hex commit SHA, or re-render with `agentsec ci add <component> --force`, which "
            "pins the release tag of the agentsec that renders it",
            check="install-unpinned",
        ))
    if _token_in_url(ln):
        out.append(Diagnosis(
            "warn", name, "agentsec install puts a token in the git URL",
            "a token in the URL lands in pip/uv's git cache and the process args, both "
            "readable by later jobs on a persistent runner; re-render with `agentsec ci add "
            "<component> --install-secret NAME --force` (token-free URL; the token reaches "
            "git only through GIT_ASKPASS)",
            check="install-token-in-url",
        ))
    return out


def _workflow_files(repo: Path) -> list[Path]:
    d = repo / ".github" / "workflows"
    if not d.is_dir():
        return []
    return sorted(p for p in d.iterdir() if p.is_file() and p.suffix in (".yml", ".yaml"))


def _read(p: Path) -> str:
    try:
        return p.read_text(encoding="utf-8")
    except OSError:
        return ""


def diagnose(repo: Path) -> list[Diagnosis]:
    """Static checks over the agentsec workflows in `repo`. Pure: reads files only."""
    out: list[Diagnosis] = []
    # Both spellings, as in check 1: a workflow whose only mention is the repo / distribution name
    # (`uses: <owner>/ai-agent-security@<sha>`, under any owner) is an agentsec workflow too.
    agentsec_wfs = [
        (p, t) for p in _workflow_files(repo)
        if "agentsec" in (low := (t := _read(p)).lower()) or "ai-agent-security" in low
    ]
    if not agentsec_wfs:
        out.append(Diagnosis(
            "warn", "-", "no agentsec workflow found under .github/workflows/",
            "install one with `agentsec ci add self-audit <repo>`",
        ))
        return out

    for p, text in agentsec_wfs:
        name = p.name
        lines = [ln.strip() for ln in text.splitlines()]

        # 1) install auth — a bare git+https URL fails on a private source repo
        for ln in lines:
            # Both spellings: the console script / import package is `agentsec`, but the
            # PyPI DISTRIBUTION is `ai-agent-security`, which does not contain "agentsec"
            # as a substring. Matching only the former would silently stop recognising a
            # `pip install ai-agent-security` line as an agentsec install (#835 rename).
            if "pip install" not in ln or not (
                "agentsec" in ln or "ai-agent-security" in ln or "git+" in ln
            ):
                continue
            if "x-access-token@" in ln and "GIT_ASKPASS" in text:
                out.append(Diagnosis(
                    "ok", name, "agentsec install is authenticated (token-free URL + GIT_ASKPASS)",
                ))
            elif _token_in_url(ln):
                continue  # authenticated, but by leaking the token: check 5 says so, not "ok"
            elif "git+https://" in ln and "${" not in ln:
                out.append(Diagnosis(
                    "warn", name, "agentsec installed from a git URL with no token",
                    "if that repo is private the runner can't clone it (\"could not read "
                    "Username\"); re-install with `--install-secret <SECRET>`, or publish to PyPI",
                ))
            else:
                out.append(Diagnosis("ok", name, "agentsec install is authenticated or public"))

        # 2) gate determinism — a gating `agentsec audit` (no --no-fail) must be reproducible
        for ln in lines:
            if "agentsec audit" not in ln or "--no-fail" in ln:
                continue
            if ln.lstrip("- ").startswith("name:"):  # a step name, not a command
                continue
            if "--deterministic" in ln or "--guards-only" in ln:
                out.append(Diagnosis("ok", name, "gate is deterministic"))
            else:
                out.append(Diagnosis(
                    "warn", name, "gate is non-deterministic",
                    "add `--deterministic`: the gate otherwise runs whatever scanner is on the "
                    "runner (e.g. node-audit via npm), whose live-advisory findings aren't "
                    "reproducible" + (" and break the snapshot ratchet"
                                      if "--baseline-snapshot" in ln else ""),
                ))

        # 3) referenced baseline snapshot must exist on disk
        for ln in lines:
            if "agentsec audit" not in ln:  # only the gate command, never a comment mentioning the flag
                continue
            i = ln.find("--baseline-snapshot ")
            if i == -1:
                continue
            out.extend(_baseline_diags(repo, name, ln[i + len("--baseline-snapshot "):].split()[0]))

        # 4) code scanning needs GitHub Advanced Security
        if "codeql-action/upload-sarif" in text:
            out.append(Diagnosis(
                "warn", name, "uploads SARIF to GitHub code scanning",
                "the Security/code-scanning tab needs GitHub Advanced Security (private repos "
                "403); for a private repo use the SARIF artifact or the run summary instead",
            ))

        # 5) the install source itself: pinned (install-unpinned) and token-free
        # (install-token-in-url). Read off the git URL, not the install verb, so a URL on a
        # continuation line (`GIT_ASKPASS=... \` then the URL) and `uv tool install` are both
        # seen. Comment lines are skipped: a URL quoted in prose is not an install.
        for ln in lines:
            if ln.startswith("#"):
                continue
            out.extend(_install_ref_findings(name, ln))

        # 6) agentsec's GitHub Action (what `ci add self-audit` renders): checks 1, 2, 3 and 5
        # for the action's form, which carries no `pip install` or `agentsec audit` line.
        out.extend(_action_diags(repo, name, text))

    return out


def _baseline_diags(repo: Path, name: str, rel: str) -> list[Diagnosis]:
    """The gate's `--baseline-snapshot` (or the action's `baseline-snapshot:`) must exist."""
    if not (repo / rel).is_file():
        return [Diagnosis(
            "error", name, f"gate references a missing baseline snapshot: {rel}",
            "generate it with `agentsec ci add self-audit --with-baseline`, or "
            "`agentsec audit <path> --save-snapshot <path>`",
        )]
    out = [Diagnosis("ok", name, f"baseline snapshot present: {rel}")]
    n_legacy = legacy_schema_rows(load_snapshot(repo / rel))
    if n_legacy:
        out.append(Diagnosis(
            "warn", name, f"baseline predates the superseded verdict: {rel}",
            f"{n_legacy} SQL finding(s) in it stay exempt even if a schema dump that "
            "answered them goes away; re-save it (with the schema dump in place, if the "
            f"repo ships one): `agentsec audit <path> --deterministic --save-snapshot {rel} "
            "--no-fail`",
        ))
    return out


def _action_diags(repo: Path, name: str, text: str) -> list[Diagnosis]:
    """Pin, reach, determinism and baseline checks for steps that use agentsec's action."""
    out: list[Diagnosis] = []
    steps = _steps_using(text)

    def is_agentsec_checkout(step: _ActionStep) -> bool:
        return step.uses.startswith("actions/checkout@") and _is_agentsec_repo(step.with_.get("repository", ""))

    # Where this workflow checked agentsec's repo out: a `uses: ./<there>` runs agentsec's action.
    local_dirs = {_local_path(s.with_["path"]) for s in steps if is_agentsec_checkout(s) and s.with_.get("path")}
    for step in steps:
        if is_agentsec_checkout(step):
            # The private-repo form: the agentsec repo checked out, then `uses: ./<dir>`.
            if (d := _action_pin_diag(name, "is checked out at", step.with_.get("ref", ""))):
                out.append(d)
            if step.with_.get("token"):
                out.append(Diagnosis("ok", name, "agentsec action checkout is authenticated (token secret)"))
            else:
                out.append(Diagnosis(
                    "warn", name, "agentsec repo checked out with no token",
                    "if that repo is private the runner can't clone it (\"Repository not found\"); "
                    "re-render with `agentsec ci add self-audit --install-secret <SECRET> --force`",
                ))
            continue
        if not _is_agentsec_action(step.uses, local_dirs):
            continue
        if not step.uses.startswith("./"):
            ref = step.uses.split("@", 1)[1]
            if (d := _action_pin_diag(name, "is used at", ref)):
                out.append(d)
            # Information, not a warning: doctor cannot tell offline whether that repository is
            # public, and this is the form `ci add self-audit` renders by default (a warning on
            # every fresh render would teach users to ignore the verdict).
            out.append(Diagnosis(
                "info", name, "agentsec action used from another repository",
                "a remote `uses:` works only while that repository is public (or owned by the same "
                "account); for a private agentsec repo re-render with `agentsec ci add self-audit "
                "--install-secret <SECRET> --force`, which checks it out with a token",
            ))
        if not step.readable:
            out.append(Diagnosis(
                "info", name, "could not read the inputs of agentsec's action step",
                "ci doctor reads `with:` as a block or a one-line `{ key: value }` mapping; with any "
                "other form it did not check this step's determinism or baseline snapshot",
            ))
            continue
        mode = step.with_.get("mode", "gate")
        if mode != "advisory":
            if step.with_.get("scanners", "deterministic") == "all":
                out.append(Diagnosis(
                    "warn", name, "gate is non-deterministic",
                    "drop `scanners: all` (the default, deterministic, is reproducible): the gate "
                    "otherwise runs whatever scanner is on the runner, whose live-advisory "
                    "findings aren't reproducible"
                    + (" and break the snapshot ratchet" if step.with_.get("baseline-snapshot") else ""),
                ))
            else:
                out.append(Diagnosis("ok", name, "gate is deterministic"))
        if (snap := step.with_.get("baseline-snapshot")):
            out.extend(_baseline_diags(repo, name, snap))
    return out


_ICON = {"ok": "✓", "info": "ℹ", "warn": "⚠", "error": "✗"}


def render(diags: list[Diagnosis]) -> str:
    lines = ["# agentsec CI doctor", ""]
    for d in diags:
        lines.append(f"{_ICON.get(d.level, '?')} [{d.workflow}] {d.title}")
        if d.fix:
            lines.append(f"    → {d.fix}")
    n_err = sum(1 for d in diags if d.level == "error")
    n_warn = sum(1 for d in diags if d.level == "warn")
    verdict = "all clear" if not (n_err or n_warn) else f"{n_err} error(s), {n_warn} warning(s)"
    lines += ["", verdict]
    return "\n".join(lines) + "\n"


def has_errors(diags: list[Diagnosis]) -> bool:
    return any(d.level == "error" for d in diags)
