"""Base class + helpers for the deterministic-scanner runners."""
from __future__ import annotations

import os
import shutil
import subprocess  # nosec B404 (subprocess orchestrates external scanners; no shell)
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from agentsec.checkmeta import UNDECLARED_AREA, Tier
from agentsec.detect import StackProfile
from agentsec.findings import Finding
from agentsec.walk import DEFAULT_EXCLUDE_DIRS


def as_list(x: Any) -> list[Any]:
    """Coerce a value from untrusted scanner JSON to a list ([] for anything else).

    `data.get(key, [])` defaults only when the key is *absent* — an explicit JSON
    `null` (Go scanners marshal empty slices as null) returns None, and a truthy
    non-list crashes the iteration. `parse()` must never raise on shape (#420).
    """
    return x if isinstance(x, list) else []


# --- scanner-level vendored-tree exclude (#860) ------------------------------
#
# `hadolint`/`pip_audit` ENUMERATE their own files and drop anything under a
# `DEFAULT_EXCLUDE_DIRS` segment before handing the list to the binary. `bandit`/`semgrep`/`trivy`
# instead hand a DIRECTORY (often the repo root) to the binary and let IT recurse, so that
# file-level filter never runs — the scanner walks straight into a gitignored `.venv/site-packages`
# and reports third-party code under the user's repo path (#860). These helpers push the SAME
# `DEFAULT_EXCLUDE_DIRS` policy down to the binary as a scanner-level exclude.
#
# The glob form is load-bearing and the THREE scanners each want a DIFFERENT one — every form
# verified against the real binary (bandit 1.9.x / semgrep 1.177 / trivy 0.73), not assumed from
# the flag being present (review-doctrine Rule 2/Rule 3). Do NOT "unify" them: each was proven, and
# another scanner's form silently fails to match a (top-level or nested) vendored dir. The measured
# divergence:
#   bandit  `-x '*/name/*'`      fnmatches the FULL path; a bare name never matches
#   semgrep `--exclude name`     matches path SEGMENTS; `*/name/*` misses a top-level dir
#   trivy   `--skip-dirs '**/name/**'`  doublestar; a bare name misses a NESTED dir (e.g. editor/.venv)


def bandit_exclude_arg() -> str:
    """A `-x` value that keeps bandit's recursive scan out of vendored/generated trees (#860).

    bandit's `-x` fnmatches the FULL path, so a bare `.venv` does NOT match — the exclude must
    be `*/.venv/*` (segment-anchored, matches at any depth AND under an absolute target path;
    verified against bandit 1.9.x). This is the OPPOSITE of semgrep's convention below."""
    return ",".join(f"*/{d}/*" for d in sorted(DEFAULT_EXCLUDE_DIRS))


def semgrep_exclude_args() -> list[str]:
    """`--exclude` args that keep semgrep out of vendored/generated trees (#860).

    semgrep already skips these via its BUILT-IN `.semgrepignore` defaults — but a repo that
    ships its own `.semgrepignore` REPLACES those defaults, silently re-exposing `.venv` (verified
    against semgrep 1.177). Passing the excludes explicitly restores the `DEFAULT_EXCLUDE_DIRS`
    floor the guards enforce. semgrep matches path SEGMENTS, so the form is the BARE dir name —
    bandit's `*/.venv/*` glob fails to match a top-level `.venv` here (verified).

    Trade-off (PR #870 review, Medium): these excludes are an unconditional FLOOR applied on top of
    `.semgrepignore`, so a repo that deliberately UN-ignores one of these names (e.g. `!build/` to
    scan a real hand-written `build/`) is overridden here with no disclosure. Accepted, and
    consistent with `DEFAULT_EXCLUDE_DIRS` being "independent of any `.gitignore`" (see walk.py) —
    the same floor the guards already enforce on that exact directory."""
    args: list[str] = []
    for d in sorted(DEFAULT_EXCLUDE_DIRS):
        args += ["--exclude", d]
    return args


def trivy_skip_dirs_args() -> list[str]:
    """`--skip-dirs` args that keep `trivy fs` out of vendored/generated trees (#860).

    `trivy fs` runs `secret` + `misconfig` over the whole recursive walk (not just the `vuln`
    package inventory), so it anchors secret/misconfig findings INSIDE a gitignored `.venv` exactly
    like bandit did — measured against trivy 0.73. trivy's `--skip-dirs` uses doublestar globs, and
    a bare `.venv` misses a NESTED `editor/.venv` (the field-report shape) — only `**/.venv/**`
    drops it (verified). This also removes `site-packages` from the `vuln` scanner's reach, but in
    practice nothing is lost: trivy inventories `vuln` from lock/requirements files, and those live in
    the user's tree (still scanned, and covered by `pip_audit`) — an installed `.venv` with no lock
    file of its own yields no `vuln` findings either way (measured against trivy 0.73: user-tree
    lock-file CVEs preserved, only the vendored secret/misconfig mis-attribution dropped)."""
    args: list[str] = []
    for d in sorted(DEFAULT_EXCLUDE_DIRS):
        args += ["--skip-dirs", f"**/{d}/**"]
    return args


@dataclass
class RunnerResult:
    runner_id: str
    available: bool
    findings: list[Finding] = field(default_factory=list)
    error: str | None = None


def which(binary: str) -> str | None:
    """Locate `binary` on PATH, falling back to the agentsec-managed bin dir.

    System PATH wins (least surprising). The managed-dir fallback lets tools
    installed by `agentsec setup` be found with no PATH editing by the user.
    """
    found = shutil.which(binary)
    if found:
        return found
    from agentsec.tooling import managed_bin_dir  # local import: avoid an import cycle

    cand = managed_bin_dir() / binary
    return str(cand) if cand.exists() else None


def child_env() -> dict[str, str]:
    """`os.environ` with the agentsec-managed bin dir *appended* to PATH.

    Runners invoke scanners by bare name (e.g. ``bandit``), so the subprocess
    resolves them via PATH. Appending the managed dir lets `agentsec setup`-
    installed tools run with no user PATH edits, while keeping system installs
    first (consistent with `which()`, which also prefers the system copy).
    """
    from agentsec.tooling import managed_bin_dir

    env = dict(os.environ)
    mbd = str(managed_bin_dir())
    path = env.get("PATH", "")
    if mbd not in path.split(os.pathsep):
        env["PATH"] = f"{path}{os.pathsep}{mbd}" if path else mbd
    return env


# Cap on captured/ingested scanner output. A hostile scanned repo can make a scanner
# emit effectively unbounded stdout (memory DoS, same class as #419). Truncation
# corrupts JSON by design: parse() then degrades to the "could not parse scanner
# output" info finding, which is the disclosure. (Peak memory during capture is still
# proportional to actual output; the cap bounds what is retained and processed.) #420
CAPTURE_CAP = 50_000_000


def exec_capture(
    args: list[str], cwd: Path, timeout: int = 300, env_extra: dict[str, str] | None = None
) -> tuple[int, str, str]:
    """Run a command, capturing stdout/stderr. Never raises (returns rc=-1 on error).

    Decodes as UTF-8 with `errors="replace"` — the platform default (cp1252 on
    Windows) raised `UnicodeDecodeError` straight through the except tuple below
    and corrupted locations/fingerprints when it did decode (#420).

    `env_extra` overlays onto `child_env()` — used to disable a scanner's own network
    egress (version-check / telemetry pings) via env vars, which an older scanner
    version silently ignores (unlike an unknown CLI flag, which would make it exit
    non-zero and drop all output). Mirrors the tool-adoption doctrine's "external
    scanners get no egress" (the adoption-time analogue of G5).
    """
    env = child_env()
    if env_extra:
        env.update(env_extra)
    try:
        p = subprocess.run(  # noqa: S603  # nosec B603 (fixed argv, no shell)
            args, cwd=cwd, capture_output=True, timeout=timeout,
            check=False, env=env, encoding="utf-8", errors="replace",
        )
        return p.returncode, p.stdout[:CAPTURE_CAP], p.stderr[:CAPTURE_CAP]
    except (subprocess.SubprocessError, OSError) as e:
        return -1, "", str(e)


def scanner_reported_errors(check_id: str, data: Any, key: str = "errors") -> list[Finding]:
    """Turn a scanner's own self-reported per-file errors into one disclosed `info` finding.

    bandit, semgrep and friends emit an `errors[]` array alongside `results[]` for files
    they could not parse or rules they could not load. Dropping it meant a scan that
    silently skipped half the tree read as a full one (#432 review) — a partial result
    presented as complete. Total (never raises on shape): anything unexpected yields []."""
    if not isinstance(data, dict):
        return []
    errors = as_list(data.get(key))
    if not errors:
        return []
    details = "; ".join(str(e)[:200] for e in errors[:10])
    if len(errors) > 10:
        details += f"; (+{len(errors) - 10} more)"
    return [
        Finding(
            check_id=check_id,
            severity="info",
            title=f"{check_id}: scanner reported {len(errors)} error(s) — coverage is incomplete",
            message=(
                "The scanner ran but could not process part of its input, so these results "
                f"do not cover the whole tree: {details}"
            ),
            remediation=(
                "Re-run the scanner directly on the affected paths to see the full error. "
                "Treat this run as partial coverage, not a clean result."
            ),
            rule=f"{check_id}/scanner-errors",
        )
    ]


class ScannerExecError(RuntimeError):
    """The scanner binary failed to launch or timed out (rc == -1 from exec_capture)."""


def exec_capture_or_raise(
    args: list[str],
    cwd: Path,
    timeout: int = 300,
    env_extra: dict[str, str] | None = None,
    allow_empty_on_error: bool = False,
) -> tuple[int, str, str]:
    """`exec_capture`, but a scanner that did not produce a report raises instead of
    returning a result the caller will read as "ran, clean".

    Two failure shapes raise:

    - **rc == -1** — the binary never launched, or timed out.
    - **rc != 0 with no output** — the binary launched and failed: bad config, OOM kill,
      permission error, unreadable target. This is the commoner case in practice, and
      covering only rc == -1 left it reporting clean for 9 of 10 runners (#432 review,
      verified with real subprocesses for bandit, trivy, eslint and gitleaks). A scanner's
      own non-zero exit meaning "I found something" always comes WITH a report on stdout, so
      keying on empty output separates the two without a per-scanner exit-code table.

    `allow_empty_on_error=True` opts a call out of the second rule, for a scanner with a
    documented "non-zero and silent is normal" path.
    """
    rc, out, err = exec_capture(args, cwd, timeout=timeout, env_extra=env_extra)
    if rc == -1:
        raise ScannerExecError(err or "scanner failed to launch")
    if rc != 0 and not out.strip() and not allow_empty_on_error:
        raise ScannerExecError(
            err.strip() or f"scanner exited {rc} without producing a report"
        )
    return rc, out, err


class Runner:
    """An external-scanner wrapper. Subclasses set id/binary and implement
    `applies`, `invoke` (returns raw scanner output), and `parse`."""

    id: str = ""
    binary: str = ""
    install_hint: str = ""
    # Reporting metadata the check declares about itself, read through `registry.check_meta()`.
    # Central id-keyed maps in `findings.py`/`registry.py` used to answer these at a distance from
    # the check that knows the answer; #617 proved the declaration belongs here (BB4).
    # Deliberately DUPLICATED from `Guard` rather than hoisted into a shared base: `Guard` and
    # `Runner` share no ancestor today, and a new inheritance edge into two hot base classes is a
    # steep price for four lines. `checkmeta.CheckMeta` is the structural protocol that lets
    # callers treat a guard and a runner uniformly without one.
    area: str = UNDECLARED_AREA          # a value from `checkmeta.AREA_ORDER`; required
    tier: Tier = "stack"                 # "baseline" = universal hygiene, independent of stack
    surfacing: bool = False              # flags an architecture for review, does not prove a bug
    surfacing_rule_prefixes: tuple[str, ...] = ()   # per-RULE surfacing, when the whole check is not
    schema_state: bool = False           # reads `.sql` as schema state, so a dump can supersede it
    # Network-egress tier this runner needs to run (the G5 policy, RFC #135). 0 = no egress
    # (local scanners: bandit/semgrep/eslint/gitleaks/hadolint) — never tier-gated. ≥1 = phones
    # out, so the audit loop skips it (disclosed) when the active --network tier is lower.
    # `egress_dest`/`egress_sends` feed the disclosure (the `agentsec network` manifest/report).
    tier_required: int = 0
    egress_dest: str = ""
    egress_sends: str = ""
    # `deterministic` runners produce reproducible output from the repo bytes + pinned
    # rules (guards, bandit, semgrep, gitleaks, hadolint, eslint). `deterministic = False`
    # marks **live-advisory** scanners that query an external DB whose contents drift over
    # time (node-audit→registry, pip-audit→OSV, trivy→CVE DB, react-doctor→Socket): great
    # for depth, but their findings can't be baselined and make a CI gate non-reproducible.
    # `audit(deterministic=True)` (and any `--write-baseline` run) excludes the False ones.
    deterministic: bool = True

    # Per-item failures recorded by a multi-target `invoke()` (several requirements files,
    # several Dockerfiles, `npm audit signatures` alongside the CVE scan). Reset by `run()`
    # before each invoke; drained after it. A partial failure USED to be discarded unless
    # every item failed, so one timed-out requirements file next to one that returned a CVE
    # produced `available=True, findings=1, error=None` — half the dependency surface
    # unscanned and indistinguishable from a full scan (#432 review).
    _partial_failures: list[str] = []

    def note_partial_failure(self, detail: str) -> None:
        """Record that part of a multi-target scan failed while the rest succeeded."""
        self._partial_failures.append(detail)

    def applies(self, profile: StackProfile) -> bool:  # noqa: ARG002
        raise NotImplementedError

    def binary_name(self, profile: StackProfile) -> str:  # noqa: ARG002
        """The binary to look up — overridable for tools chosen per stack (npm/pnpm)."""
        return self.binary

    def invoke(self, root: Path, profile: StackProfile) -> str:  # noqa: ARG002
        """Run the scanner and return its raw (JSON) output."""
        raise NotImplementedError

    def parse(self, raw: str) -> list[Finding]:  # noqa: ARG002
        """Parse raw scanner output into Findings. Must never raise on shape."""
        raise NotImplementedError

    def coverage_note(self, profile: StackProfile) -> str | None:  # noqa: ARG002
        """Disclose that this runner is about to run with a **reduced** rule/check set.

        Honest-coverage contract (issue #434): a runner that still runs, but with fewer
        rules than its full configuration, is otherwise indistinguishable in the report
        from a full-coverage run — it is not `unavailable`, not `offline_skipped`, not
        `errored`, and appears plainly under *Checks run*. Any runner whose rule set
        varies with the active configuration (today: semgrep, whose OSS registry packs
        are tier-1) MUST return a one-line reason here so `audit()` can record it in
        `AuditResult.tools_reduced` and every emitter (markdown footer + SARIF
        `toolExecutionNotifications`) can disclose it.

        Return `None` (the default) when the runner is at full strength."""
        return None

    def run(self, root: Path, profile: StackProfile) -> RunnerResult:
        if which(self.binary_name(profile)) is None:
            return RunnerResult(self.id, available=False)
        self._partial_failures = []
        try:
            raw = self.invoke(root, profile)
        except Exception as e:  # noqa: BLE001 - a scanner crash must not abort the audit
            return RunnerResult(self.id, available=True, error=f"{type(e).__name__}: {e}")
        partial = list(self._partial_failures)
        try:
            findings = self.parse(raw)
        except Exception as e:  # noqa: BLE001 - a parse error becomes one info finding, not a crash
            return RunnerResult(
                self.id,
                available=True,
                findings=[
                    Finding(
                        check_id=self.id,
                        severity="info",
                        title=f"{self.id}: could not parse scanner output",
                        message=f"{type(e).__name__}: {e}",
                    )
                ],
                error=str(e),
            )
        if not partial:
            return RunnerResult(self.id, available=True, findings=findings)
        # A partial scan is NOT a clean scan. Both channels are set: an `info` finding so the
        # gap is visible in every output format (markdown AND SARIF), and `error` so the
        # runner lands in the report's `tools_errored` list rather than under "Checks run".
        detail = "; ".join(partial)
        findings.append(
            Finding(
                check_id=self.id,
                severity="info",
                title=f"{self.id}: scan was incomplete — some targets could not be scanned",
                message=(
                    f"{len(partial)} target(s) failed while others succeeded, so these results "
                    f"cover only part of the surface: {detail}"
                ),
                remediation=(
                    "Re-run the scanner on the failing target(s) directly to see its error. "
                    "Treat this run as partial coverage, not a clean result."
                ),
                rule=f"{self.id}/partial-scan",
            )
        )
        return RunnerResult(self.id, available=True, findings=findings, error=f"partial scan: {detail}")
