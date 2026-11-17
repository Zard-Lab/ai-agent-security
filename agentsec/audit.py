"""Audit orchestration: detect → select → run guards (+ scanners) → findings,
then apply the exception/baseline registry."""
from __future__ import annotations

import fnmatch
import functools
import re
import sys
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path

from agentsec import walk
from agentsec.astutil import (
    ParseCandidates,
    parse_failure_candidates,
    parse_failure_reason,
    parse_failure_run,
)
from agentsec.compounding_risk import assess as assess_compounding_risk
from agentsec.config import load_repo_config
from agentsec.crosscheck import crosscheck
from agentsec.detect import StackProfile, detect
from agentsec.exceptions import DEFAULT_REGISTRY, apply_exceptions, load_exceptions, load_local_exceptions
from agentsec.findings import Finding, normalize_location
from agentsec.guards.base import derived_state_run, read, read_run
from agentsec.registry import ALL_GUARDS, select_guards, select_runners
from agentsec.sql_state import build_sql_state, governing_dump
from agentsec.walk import walk_files

_LOC_LINE_SUFFIX = re.compile(r":\d+(?::\d+)?$")
_UNPARSED_SHOWN = 5  # files named in the #1001 notice; the rest are counted


@dataclass
class AuditResult:
    profile: StackProfile
    findings: list[Finding]
    ran: list[str]
    skipped: list[str]
    tools_unavailable: list[str] = field(default_factory=list)
    tools_errored: list[str] = field(default_factory=list)
    tools_offline_skipped: list[str] = field(default_factory=list)  # egressing runners skipped below their tier
    # Runners that RAN but with a reduced rule/check set at the active configuration (#434).
    # Each entry is a rendered "<runner-id> — <reason>" line (mirrors harden-host's probe
    # disclosure style). Distinct from `tools_errored`/`tools_offline_skipped`: the scanner
    # worked, it just covered less, which is otherwise invisible in the report.
    tools_reduced: list[str] = field(default_factory=list)
    suppressed: list[Finding] = field(default_factory=list)   # accepted via the registry
    lapsed: list[str] = field(default_factory=list)            # expired-exception reminders
    # Waivers that suppressed MORE THAN ONE finding, already rendered (#507). A waiver is
    # written about one finding; when one covers several, the extras are real findings that
    # went quiet. Rendered by `ExceptionOutcome.broad_waivers()`; empty = every waiver
    # covered exactly one finding.
    broad_waivers: list[str] = field(default_factory=list)
    # Waivers that matched NOTHING while the check that owns them ran, already rendered
    # (#730). The mirror of `broad_waivers`: a waiver whose finding was fixed at source is
    # otherwise invisible until it lapses, and the lapse reminder then describes it wrongly.
    # Empty when the run was scope-narrowed (see `audit()`), because a waiver for a file this
    # run never looked at matched nothing for a reason that has nothing to do with being dead.
    unused_waivers: list[str] = field(default_factory=list)
    # Dead waivers whose finding is still present under a new fingerprint, already rendered
    # (#896): a reworded guard message shifts the identity of every finding of that rule.
    # Kept apart from `unused_waivers` so the report never labels a still-live accepted-risk
    # record "unused". Rendered by `ExceptionOutcome.drifted_waivers()`; same scope gate.
    drifted_waivers: list[str] = field(default_factory=list)
    excluded: list[Finding] = field(default_factory=list)      # dropped by --exclude patterns
    local_suppressed: list[Finding] = field(default_factory=list)  # subset of `suppressed` from .agentsec/suppress.json
    archive_excluded: list[Finding] = field(default_factory=list)  # dropped — under a configured .agentsec archive_paths tree
    crosscheck_deduped: int = 0  # duplicate Splinter findings folded into a confirmed static one
    crosscheck_splinter_objects: int = 0  # distinct (lint, object) among splinter-only findings
    # Guards KILLED over the per-guard time budget (#677) — their checks did not complete, so
    # the scan is partial in a way no finding can show. Distinct from `tools_errored` (which
    # ran to a crash) and from every skip state: this is the one state that fails the gate
    # unconditionally (see cli._gate), because the alternative was a hung job whose external
    # kill reports nothing — the canonical "failure that presents as success" (Rule 3).
    # A state channel on purpose, never a Finding: it must not be baselinable or waivable.
    guards_budget_exceeded: list[str] = field(default_factory=list)
    # The guard worker child never started (#677 fallback): the guards still ran — through
    # the legacy in-process loop — so COVERAGE is complete, but the hang protection lapsed
    # from that point on. A coverage notice, not a gate failure: nothing is missing from the
    # scan; what is missing is the guarantee that a hang would have been preempted.
    guards_unbudgeted: bool = False
    # Python files a check tried to parse and could not (#1001), as sorted (repo-relative path,
    # parser message) pairs. Each was confirmed by a whole-file parse, so a fragment that failed
    # on its own never lands here. The AST-based checks skipped these files or fell back to a text
    # scan, and before this field nothing in the report said so. A coverage notice, not a gate
    # failure: the gap is per file and named, unlike a killed guard. Paths the user scoped out
    # (`--exclude`, archive trees) are left out.
    unparsed_python: list[tuple[str, str]] = field(default_factory=list)
    unparsed_python_truncated: bool = False  # the candidate record hit its cap; more may exist

    def unparsed_python_notice(self) -> tuple[str, str] | None:
        """The #1001 disclosure as (label, detail), or None when nothing needs disclosing.

        One builder for every renderer: `coverage_notices()` (SARIF), the markdown footer and
        the triage header each join the two parts in their own style."""
        if not (self.unparsed_python or self.unparsed_python_truncated):
            return None
        label = (
            f"Python files that could not be parsed by Python {sys.version_info.major}."
            f"{sys.version_info.minor} (AST-based checks skipped them or fell back to a text scan)"
        )
        shown = self.unparsed_python[:_UNPARSED_SHOWN]
        parts = [", ".join(f"{path} ({why})" for path, why in shown)] if shown else []
        if len(self.unparsed_python) > len(shown):
            parts.append(f"+{len(self.unparsed_python) - len(shown)} more")
        if self.unparsed_python_truncated:
            parts.append("the record of failed parses hit its cap, so more files may be affected")
        return label, f"{len(self.unparsed_python)} file(s): " + "; ".join(parts)

    def coverage_notices(self) -> list[str]:
        """Every reason this run may have seen LESS than a full-coverage scan, as plain lines.

        The single source for the honest-coverage disclosure, so it can travel with any
        emitter rather than only the markdown footer (#434). Before this, SARIF carried no
        part of the scanner-disclosure channel at all — a `--format sarif` CI run (the
        documented CI path) was indistinguishable from a clean full-coverage run even when
        a scanner was missing, tier-skipped, reduced, or crashed. Empty list = nothing to
        disclose; absence of a notice is then a real signal, not a rendering gap."""
        out: list[str] = []
        if self.tools_unavailable:
            out.append(
                "Scanners not installed (skipped): " + ", ".join(self.tools_unavailable)
            )
        if self.tools_offline_skipped:
            out.append(
                "Scanners skipped (offline — raise `--network` to enable): "
                + ", ".join(self.tools_offline_skipped)
            )
        out.extend(f"Reduced coverage: {n}" for n in self.tools_reduced)
        if self.tools_errored:
            out.append("Scanners that errored: " + ", ".join(self.tools_errored))
        if (unparsed := self.unparsed_python_notice()) is not None:
            out.append(f"{unparsed[0]}: {unparsed[1]}")
        if self.guards_budget_exceeded:
            out.append(
                "Guards killed over their time budget — their checks did NOT complete: "
                + ", ".join(self.guards_budget_exceeded)
            )
        if self.guards_unbudgeted:
            out.append(
                "Guard time budget DISABLED for this run (worker failed to start; the remaining "
                "guards ran in-process, unbudgeted — a hung guard would not have been preempted)"
            )
        return out

    @property
    def checks_run_clean(self) -> list[str]:
        """The checks that RAN and could have produced results — for the positive
        "Checks run" inventory (#895).

        `ran` means *attempted*, not *ran clean*: a guard/runner that crashed or
        partial-scanned lands in BOTH `ran` and `tools_errored` (runners/base.py's
        invoke-crash + partial-scan shapes; the budgeted guard worker double-lists an
        errored guard the same way). Rendering raw `ran` as "Checks run" therefore claims
        coverage for a check that errored — a Rule-3 coverage-honesty misreport. Subtract
        the errored set so the positive inventory names only checks that actually ran;
        every excluded id is still disclosed under "Scanners that errored". Budget-exceeded
        guards are already held out of `ran` upstream (guard_worker excludes KILLED guards),
        so there is nothing to subtract for them here."""
        errored = set(self.tools_errored)
        return [c for c in self.ran if c not in errored]


def _matches_excludes(location: str, patterns: list[str]) -> bool:
    """True if a finding `location` falls under any user `--exclude` pattern.

    Intuitive CLI semantics (not gitignore): a pattern matches when it equals the
    path, is an ancestor directory of it, glob-matches it, or — for a bare name —
    appears as any path segment. The `:line[:col]` suffix is stripped first."""
    if not location:
        return False
    path = _LOC_LINE_SUFFIX.sub("", location).replace("\\", "/")
    segments = path.split("/")
    for raw in patterns:
        pat = raw.replace("\\", "/").rstrip("/")
        if not pat:
            continue
        if path == pat or path.startswith(pat + "/"):
            return True
        if fnmatch.fnmatch(path, pat) or fnmatch.fnmatch(path, pat + "/*"):
            return True
        if "/" not in pat and pat in segments:
            return True
    return False


def _gitignore_cap_findings(notices: list[walk.GitignoreCapNotice] | None = None) -> list[Finding]:
    """Disclose every `.gitignore` resource cap that tripped during this audit's walks.

    `walk.py` is inside the guard trust boundary (pathlib only — it cannot emit a
    Finding or write to stderr), so it records the trips and they surface here, in the
    same shape as the oversize-PDF read cap: an `info` finding naming the file and what
    was not applied. Silent truncation is the thing being avoided — a scan that quietly
    stopped honoring a repo's ignore rules will read as under-detection later.

    `notices` defaults to THIS process's run context; a budgeted run (#677) passes the
    worker child's notices explicitly, because the guard walks happened over there."""
    return [
        Finding(
            check_id="gitignore-cap",
            severity="info",
            title="Some .gitignore rules were not applied (resource cap)",
            location=n.path,
            message=(
                f"{n.detail}. `.gitignore` content is attacker-controlled and every rule is "
                "evaluated against every walked path, so agentsec bounds the work it will do "
                "here (issue #419). Files this repo intended to ignore may therefore have been "
                "SCANNED — an entry whose budget is spent is forced to not-ignored, so nothing is "
                "hidden, but findings under an "
                "ignored path may appear."
            ),
            remediation=(
                "Simplify or shrink this .gitignore (real-world files are well under every cap: "
                "the widest surveyed carries 141 rules / 5.8 KB). If it is machine-generated, "
                "collapse the redundant patterns; if it is not yours, treat it as hostile input."
            ),
            rule="walk/gitignore-cap-tripped",
        )
        for n in (walk.gitignore_cap_notices() if notices is None else notices)
    ]


def _confirm_unparsed(root: Path, candidates: ParseCandidates) -> list[tuple[str, str]]:
    """Each candidate file that really does not parse, as (repo-relative path, parser message).

    A candidate only says some parse that named this file failed, and the text parsed may have
    been a fragment (one function block, a string-blanked view) of a file that parses fine
    (#1001). Re-parsing the whole file once settles it. One parse per distinct candidate, run
    in the parent after the guards have finished.

    Guards name the same file differently (an absolute path, or `rel()`'s repo-relative one,
    which is relative to `root`), so candidates are de-duplicated by resolved path first."""
    files: set[Path] = set()
    for name in candidates.paths:
        path = Path(name)
        try:
            path = (path if path.is_absolute() else root / path).resolve()
            if path.is_file():
                files.add(path)
        except (OSError, ValueError):  # a synthetic name that is not a legal path here
            continue
    out: list[tuple[str, str]] = []
    for path in files:
        reason = parse_failure_reason(read(path), filename=path)
        if reason is not None:
            out.append((normalize_location(root, str(path)), reason))
    return sorted(out)


def _with_run_caches[**P, R](fn: Callable[P, R]) -> Callable[P, R]:
    """Scope the per-run caches around an audit, so work that depends only on the target
    is done once per run rather than once per registered guard.

    `walk.walk_run()` — the tree is walked ~twice instead of once per guard, and cap
    disclosures belong to this run only.

    `base.derived_state_run()` — per-file derived state (issue #544). Without it
    `strip_python_strings` runs once per (guard, file) pair: 13,867 calls over 307 distinct
    texts on agentsec's own package, 69% of the audit's time. Same guard-count multiplication
    the walk cache already solved, closed for file-derived state. Measured 2.21x, findings
    byte-identical.

    Both are re-entrant and clear on exit, so nothing is served stale between audits.

    `parse_failure_run()` is not a cache but is scoped the same way: it collects this run's
    parse-failure candidates (#1001) and nothing from any other run.

    `base.read_run()` memoises `read()` by PATH (#597), which is only sound because an audit never
    writes the tree it reads; it is the one cache keyed by path rather than content, so it is opened
    here and in the guard worker's child, never inside `derived_state_run()`. That scope also opens
    the text-keyed parse memo (`astutil.parse_cache_run()`) and the `_conditional_lines` table."""

    @functools.wraps(fn)
    def wrapper(*args: P.args, **kwargs: P.kwargs) -> R:
        with walk.walk_run(), derived_state_run(), read_run(), parse_failure_run():
            return fn(*args, **kwargs)

    return wrapper


@_with_run_caches
def audit(
    root: Path,
    run_scanners: bool = True,
    exceptions_path: Path | None = None,
    extra_findings: list[Finding] | None = None,
    today: date | None = None,
    skip_static: bool = False,
    excludes: list[str] | None = None,
    changed_paths: frozenset[str] | None = None,
    kev: bool = False,
    epss: bool = False,
    network_tier: int = 0,
    deterministic: bool = False,
    guard_budget: float | None = None,
    guard_workers: int = 1,
) -> AuditResult:
    """Run the applicable static guards (and, if installed, the deterministic
    scanners) against `root`, merge any `extra_findings` (e.g. ingested external
    reports), then apply the exception registry.

    `skip_static` (the `agentsec live --live-only` switch) bypasses the static
    guards + scanners entirely, so a live run can report ONLY the live-scanner
    findings carried in `extra_findings` (ZAP / Splinter / Schemathesis / jwt /
    garak / promptfoo) without re-running — and re-gating on — the whole static
    audit. The exception registry is still applied to the live findings.

    `guard_budget`: per-guard wall-clock seconds (issue #677). When set (> 0), guards run
    in a killable child process (`guard_worker.py`) so one stuck in a C-level loop is
    preempted for real and reported in `AuditResult.guards_budget_exceeded` instead of
    hanging the audit until an external kill that reports nothing. None/0 (the library
    default) keeps the historical in-process loop — the CLI paths that face hostile or
    unbounded input (`audit`, `live`, `scan`, corpus-scan) pass `DEFAULT_GUARD_BUDGET`.

    `guard_workers`: how many budgeted children run the guards in parallel (default 1, one
    child). Findings, `ran` and the disclosures come back in the same order whatever the
    count. Only meaningful with `guard_budget` > 0; the in-process path is always serial.

    `changed_paths`: when set (from `--changed-files-only`), only findings whose
    location falls within the changed file set are kept. The set contains
    repo-relative path strings (forward-slash-normalized) as returned by
    `git diff --name-only`."""
    today = today or date.today()
    profile = detect(root)
    # #894: detect() resolved its own copy into `profile.root` (absolute); reuse THAT one
    # absolute root for every downstream pass — guards (:g.run), runners (:r.run) and the
    # SQL-state walk. A raw relative `root` (e.g. `agentsec audit minirepo`) double-joins in
    # any runner that builds a target from `root` AND sets `cwd=root` (gitleaks/hadolint/
    # pip-audit/trivy, and bandit's `-c` config), yielding a missing `<root>/<root>` → the
    # scanner exits non-zero → its findings are silently lost. Resolve ONCE, here, at the
    # single chokepoint every CLI entry point funnels through.
    root = profile.root
    # Thread the audit date onto the profile so guards that need it (e.g. CVE-waiver
    # expiry) read it explicitly instead of calling date.today() — keeping guards pure
    # functions of (file bytes + profile). `review_by` stays the ONE allowed time input.
    profile.today = today
    # Opt-in: a repo's `.agentsec/config.json` can mark archive/dead-code trees so the
    # guards skip them (DROP), and non-product trees so findings there are DEMOTED (default:
    # nothing changed). detect() stays pure; this is the one place that reads per-repo config.
    # See `config.load_repo_config`.
    _repo_config = load_repo_config(root)
    profile.archive_segments = _repo_config.archive_segments
    profile.nonproduct_segments = _repo_config.nonproduct_segments
    # Run-scoped: let tier-aware runners see the active egress tier without a full
    # tier-gate. semgrep uses this to run its pinned local pack at Tier 0 and add the
    # remote registry packs only at Tier >= 1 (issue #421). detect() stays pure.
    # Capped to 0 in deterministic mode: a --deterministic run (CI gate / baseline) must
    # be reproducible, and the tier>=1 registry packs drift upstream — so even at
    # --network tier1/--kev, a deterministic run keeps semgrep on its pinned local pack
    # (the tier-1 advisory runners are already excluded by the r.deterministic gate below).
    profile.network_tier = 0 if deterministic else network_tier
    findings: list[Finding] = []
    ran: list[str] = []
    unavailable: list[str] = []
    errored: list[str] = []
    skipped: list[str] = []
    offline_skipped: list[str] = []  # egressing runners skipped because the active tier is too low
    reduced: list[str] = []  # runners that ran with a reduced rule set (#434)
    budget_exceeded: list[str] = []  # guards killed over the per-guard time budget (#677)
    guards_unbudgeted = False  # the worker never started; guards ran through the legacy loop
    child_cap_findings: list[Finding] = []  # gitignore-cap trips from the worker child's walks
    child_parse_candidates = ParseCandidates()  # parse failures recorded in the worker children

    if not skip_static:
        selected_guards = select_guards(profile)
        selected_guard_ids = {g.id for g in selected_guards}
        if guard_budget and guard_budget > 0:
            # #677: run the guards in a killable child so a hang (which the except below
            # can never see — a non-returning call bypasses it) is preempted and DISCLOSED
            # instead of riding the audit into an external kill that reports nothing.
            from agentsec.guard_worker import run_guards_budgeted

            outcome_g = run_guards_budgeted(root, profile, selected_guards, guard_budget,
                                            workers=guard_workers)
            findings.extend(outcome_g.findings)
            ran.extend(outcome_g.ran)
            errored.extend(outcome_g.errored)
            budget_exceeded.extend(outcome_g.budget_exceeded)
            guards_unbudgeted = outcome_g.fallback_inprocess
            child_cap_findings.extend(_gitignore_cap_findings(outcome_g.cap_notices))
            child_parse_candidates = outcome_g.parse_candidates
        else:
            for g in selected_guards:
                try:
                    findings.extend(g.run(root, profile))
                except Exception:  # noqa: BLE001
                    # A guard crash (e.g. a malformed/hostile target file) must never abort the
                    # whole audit — mirror the runner contract (base run() swallows exceptions).
                    errored.append(g.id)
                ran.append(g.id)

        if run_scanners:
            for r in select_runners(profile):
                # Deterministic mode (CI gates / baseline generation): skip live-advisory
                # scanners whose results drift with an external DB and can't be baselined.
                # Checked first so a deterministic CI run excludes them silently (not as an
                # offline-skip), matching the F1 behavior.
                if deterministic and not r.deterministic:
                    continue
                # G5 egress gate (RFC #135): a runner that phones out (tier_required ≥ 1) is
                # skipped — disclosed (offline-skipped), not run, so nothing egresses — when the
                # active --network tier is lower. Raise --network to enable.
                if getattr(r, "tier_required", 0) > network_tier:
                    offline_skipped.append(r.id)
                    continue
                result = r.run(root, profile)
                if not result.available:
                    unavailable.append(r.id)
                    continue
                findings.extend(result.findings)
                ran.append(r.id)
                # Honest coverage (#434): a runner that RAN but with fewer rules than its
                # full configuration must say so — it is not unavailable, not tier-skipped
                # and not errored, so *Checks run* would otherwise read as full coverage.
                # Asked only for runners that actually ran: a scanner that never ran makes
                # no coverage claim to qualify. `profile` carries the (deterministic-capped)
                # tier the runner actually saw, so the note matches what really executed.
                try:
                    note = r.coverage_note(profile)
                except Exception:  # noqa: BLE001 - a disclosure hook must never abort the audit
                    note = None
                if note:
                    reduced.append(f"{r.id} — {note}")
                if result.error:
                    errored.append(r.id)

        skipped = [g.id for g in ALL_GUARDS if g.id not in selected_guard_ids]

    # Disclose any `.gitignore` resource cap tripped by the walks above (detect() +
    # every guard). Emitted even when `skip_static` is set: detect() still walked.
    # A budgeted run's guard walks tripped their caps in the CHILD's run context
    # (`child_cap_findings`); the same tree walked in both processes trips the same
    # caps, so dedupe by content rather than disclosing each trip twice (#677).
    seen_caps: set[tuple[str, str, str]] = set()
    for cap_f in _gitignore_cap_findings() + child_cap_findings:
        cap_key = (cap_f.rule, cap_f.location, cap_f.message)
        if cap_key not in seen_caps:
            seen_caps.add(cap_key)
            findings.append(cap_f)

    if extra_findings:
        findings.extend(extra_findings)

    # --- normalize every location to repo-relative (portable baselines + SARIF) ---
    # Guards already emit `rel()` paths (no-op here); the external-scanner runners
    # emit absolute paths, which become machine-independent at this boundary so a
    # baseline/fingerprint written on one checkout matches on another. Done BEFORE
    # the --exclude filter so user patterns match the normalized (relative) paths.
    for f in findings:
        f.location = normalize_location(profile.root, f.location)

    # --- archive trees (.agentsec/config.json archive_paths) — drop across ALL guards ---
    # The per-guard `is_nonproduct_path` skip only covers noise-prone guards; this universal
    # pass also drops whole-file guards' findings (dependency-version-floor, rls-*, …) under a
    # configured archive tree, so opting a tree in fully removes it (not just partially). Opt-in
    # (empty by default); non-configured archives are only DEMOTED by `prioritize`, never dropped.
    # Runs before --exclude / the registry so archived findings never reach suppression or counts.
    archive_excluded: list[Finding] = []
    if profile.archive_segments:
        kept_arch: list[Finding] = []
        for f in findings:
            path = (f.location or "").replace("\\", "/").split(":", 1)[0].lower()
            dir_segments = path.split("/")[:-1]  # directory segments only (mirror is_nonproduct_path)
            target = archive_excluded if any(s in profile.archive_segments for s in dir_segments) else kept_arch
            target.append(f)
        findings = kept_arch

    # --- non-product trees (.agentsec/config.json nonproduct_paths) — DEMOTE, never drop ---
    # The softer sibling of the archive pass: a finding under a configured non-product tree
    # (e.g. `evals/`, `scripts/`) stays in the report but is stamped `nonproduct` so `prioritize`
    # ranks it low. A real bug there is never hidden — just deprioritized. Opt-in (empty default).
    if profile.nonproduct_segments:
        for f in findings:
            path = (f.location or "").replace("\\", "/").split(":", 1)[0].lower()
            dir_segments = path.split("/")[:-1]  # directory segments only (mirror is_nonproduct_path)
            if any(s in profile.nonproduct_segments for s in dir_segments):
                f.nonproduct = True

    # --- SQL schema-state: mark superseded-migration findings for demotion (never drop) ---
    # When the repo ships an authoritative schema dump (a dump-like name AND pg_dump's output
    # signature, #1037), it is the source of truth for its own subtree: SQL findings in any OTHER
    # `*.sql` file there are historical (an old policy/grant later dropped/replaced) and
    # `prioritize` sinks them below the live findings. One pass over every finding, keyed on the
    # location AND on whether the check reads SQL as schema state (`schema_state`, declared on
    # the check) — the location alone would also demote a homoglyph or a committed secret that
    # merely sits in a migration file, which no dump re-flags. See `sql_state` / guards-vs-Splinter.
    # The governing dump's path rides on the finding so the report names it (`findings.history_note`).
    sql_state = build_sql_state(root, [p for p in walk_files(root) if p.suffix == ".sql"])
    if sql_state.dumps:
        for f in findings:
            dump = governing_dump(f.location, sql_state, f.check_id)
            if dump is not None:
                f.superseded = True
                f.superseded_by = dump

    # --- static ↔ Splinter cross-confirmation (live audits only) ---
    # When Splinter findings are present (an `agentsec live` run ingested them via extra_findings),
    # tag each finding's provenance (confirmed-live / static-only / splinter-only) and dedup confirmed
    # static+Splinter pairs (keep the actionable file:line static one). TAG, never demote a static-only
    # finding — see `crosscheck` / the guards-vs-Splinter doctrine. No Splinter findings → no-op.
    xcheck = crosscheck(findings, root)
    findings = xcheck.findings

    # --- CISA KEV enrichment (Tier 1, opt-in via --kev) — BOOST known-exploited, never drop ---
    # A finding whose CVE is in the CISA Known-Exploited catalog is stamped `kev`; `prioritize`
    # leads it within its severity. Networked (the ONLY first-party egress on the audit path),
    # so it is gated on `--kev` + network tier ≥ 1, routed through net.py, and 24h-cached. Off by
    # default → a normal audit stays Tier 0 (zero egress). Degrades to a no-op on any fetch failure.
    # Gated on `profile.network_tier` (the deterministic-capped tier), NOT the raw `network_tier`
    # parameter — a `--deterministic` run must stay reproducible, and a live daily-changing
    # KEV/EPSS stamp defeats that exactly like a live scanner would (review #609 H4: the raw
    # parameter let `--deterministic --network tier1 --epss` egress and reorder the report).
    if kev and profile.network_tier >= 1:
        from datetime import UTC, datetime, time

        from agentsec import kev as _kev
        kev_set = _kev.fetch_kev(tier=profile.network_tier, now=datetime.combine(today, time.min, tzinfo=UTC))
        _kev.stamp_kev(findings, kev_set)

    # --- FIRST.org EPSS enrichment (Tier 1, opt-in via --epss) — BOOST high-probability, never drop ---
    # A finding's CVE gets its EPSS score (modeled exploitation probability); `prioritize` boosts
    # findings above a documented high-probability threshold. Queried per-CVE (only the CVEs this
    # audit already found), not a bulk download — see `epss.py`. Off by default; degrades to a
    # no-op on any fetch failure.
    if epss and profile.network_tier >= 1:
        from datetime import UTC, datetime, time

        from agentsec import epss as _epss
        cve_ids = _epss.cves_in_findings(findings)
        epss_scores = _epss.fetch_epss(
            cve_ids, tier=profile.network_tier, now=datetime.combine(today, time.min, tzinfo=UTC)
        )
        _epss.stamp_epss(findings, epss_scores)

    # --- --changed-files-only filter (drop findings outside changed set) ---
    # `None` = git failed → full scan; an empty frozenset = git ok but nothing changed →
    # scope to nothing (so an empty set must filter every finding out, not fall through).
    if changed_paths is not None:
        def _in_changed(loc: str, cp: frozenset[str]) -> bool:
            base = _LOC_LINE_SUFFIX.sub("", loc).replace("\\", "/")
            return base in cp or any(base.startswith(p + "/") for p in cp)

        findings = [f for f in findings if _in_changed(f.location, changed_paths)]

    # --- user --exclude paths (drop before the registry so they don't count) ---
    excluded: list[Finding] = []
    if excludes:
        kept: list[Finding] = []
        for f in findings:
            (excluded if _matches_excludes(f.location, excludes) else kept).append(f)
        findings = kept

    # --- exception / baseline registry (global + project-local) ---
    reg_path = exceptions_path or (root / DEFAULT_REGISTRY)
    all_exceptions = load_exceptions(reg_path) + load_local_exceptions(root)
    outcome = apply_exceptions(findings, all_exceptions, today)

    # --- compounding-risk signal — ADD, never drop or mutate existing findings ---
    # Two (or more) already-present findings can be worse together than either alone (SQLi + IDOR =
    # account takeover, not two separate mediums). Runs AFTER suppression, over `outcome.kept` only
    # (not the pre-suppression list): assessing pre-suppression let two findings the repo already
    # baselined manufacture a brand-new, unbaselined critical on every subsequent run, with no code
    # change on the repo's part (#683 review, Critical 1). The synthetic finding is then run through
    # the SAME exception registry itself, so it remains suppressible/baselineable like any other
    # finding — just as a second, independent pass, since it didn't exist for the first one to see.
    # See `compounding_risk.py` for the curated pair list and its own scope notes.
    compound = assess_compounding_risk(outcome.kept)
    if compound:
        compound_outcome = apply_exceptions(compound, all_exceptions, today)
        outcome.kept.extend(compound_outcome.kept)
        outcome.suppressed.extend(compound_outcome.suppressed)
        outcome.lapsed.extend(compound_outcome.lapsed)
        outcome.local_suppressed.extend(compound_outcome.local_suppressed)

    # --- unused-waiver disclosure (#730) ---
    # Every filter above drops findings BEFORE the registry sees them (deliberately, so
    # out-of-scope findings never reach suppression or the counts). A waiver pointing into a
    # dropped path therefore matches nothing while remaining completely live, and calling it
    # a "candidate to remove" would invite the user to delete the waivers protecting exactly
    # the tree they scoped out. Two different shapes of that, handled two different ways:
    #
    # `--exclude` / archive trees are PER-PATH, so they get a per-waiver test — excluding one
    # tree must not silence the disclosure for every other waiver, or the feature is off for
    # most real runs (agentsec's own self-audit passes `--exclude`).
    #
    # `--changed-files-only` is WHOLE-RUN: it scopes the finding set by intent rather than by
    # path, and an empty changed set filters everything out — the one case where a naive
    # complement declares the entire registry dead. Nothing is attributable on such a run.
    def _waiver_out_of_scope(location: str) -> bool:
        if excludes and _matches_excludes(location, excludes):
            return True
        if profile.archive_segments:
            path = (location or "").replace("\\", "/").split(":", 1)[0].lower()
            return any(s in profile.archive_segments for s in path.split("/")[:-1])
        return False

    unused_waivers = (
        [] if changed_paths is not None
        else outcome.unused_waivers(frozenset(ran), out_of_scope=_waiver_out_of_scope)
    )
    drifted_waivers = (
        [] if changed_paths is not None
        else outcome.drifted_waivers(frozenset(ran), out_of_scope=_waiver_out_of_scope)
    )

    # --- files a check could not parse (#1001) ---
    # The children's candidates (budgeted run) plus this process's own: the in-process loop, or
    # the budgeted run's in-process fallback. Confirmed against the whole file, then scoped like
    # the findings: a path the user excluded or archived is out of the report entirely, so it is
    # out of this notice too.
    candidates = parse_failure_candidates() | child_parse_candidates
    unparsed = [
        (path, why) for path, why in _confirm_unparsed(root, candidates)
        if not _waiver_out_of_scope(path)
    ]

    return AuditResult(
        profile=profile,
        findings=outcome.kept,
        ran=sorted(ran),
        skipped=sorted(skipped),
        tools_unavailable=sorted(unavailable),
        tools_errored=sorted(errored),
        tools_offline_skipped=sorted(offline_skipped),
        tools_reduced=sorted(reduced),
        suppressed=outcome.suppressed,
        lapsed=outcome.lapsed,
        broad_waivers=outcome.broad_waivers(),
        unused_waivers=unused_waivers,
        drifted_waivers=drifted_waivers,
        excluded=excluded,
        local_suppressed=outcome.local_suppressed,
        archive_excluded=archive_excluded,
        crosscheck_deduped=xcheck.deduped,
        crosscheck_splinter_objects=xcheck.splinter_only_objects,
        guards_budget_exceeded=sorted(budget_exceeded),
        guards_unbudgeted=guards_unbudgeted,
        unparsed_python=unparsed,
        unparsed_python_truncated=candidates.truncated,
    )
