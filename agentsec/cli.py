"""agentsec CLI — `detect`, `audit`, `trifecta`, `live`.

Exit code: `audit`/`live` return non-zero when high+ findings exist (CI gate),
unless `--no-fail` is passed. `detect`/`trifecta` are informational (always 0).
"""
from __future__ import annotations

import argparse
import collections
import json
import os
import re
import sys
from datetime import date
from pathlib import Path
from typing import TYPE_CHECKING, Any
from urllib.parse import urlsplit

from agentsec import __version__
from agentsec.audit import AuditResult
from agentsec.audit import audit as run_audit
from agentsec.console import force_utf8_stdio
from agentsec.detect import StackProfile
from agentsec.findings import (
    SEVERITY_RANK,
    Finding,
    governing_dumps,
    is_historical,
    to_github_annotations,
    to_human_summary,
    to_markdown,
    to_sarif_json,
)
from agentsec.guard_worker import DEFAULT_GUARD_BUDGET, default_guard_workers

if TYPE_CHECKING:
    from agentsec.tooling import ToolSpec


def _cmd_detect(args: argparse.Namespace) -> int:
    from agentsec.detect import detect

    prof = detect(Path(args.path))
    print(_detect_text(prof), end="")
    for line in _db_target_lines(prof.root):
        print(line)
    if prof.uncovered_stacks:
        from agentsec.gap_report import record_gaps
        record_gaps(prof.uncovered_stacks)
    return 0


def _candidate_segment(directory: str) -> str:
    """The directory-segment name the config matches on (`backend/evals` -> `evals`)."""
    return directory.rsplit("/", 1)[-1]


def _norm_accept_name(s: str) -> str:
    """One normalization for BOTH sides of the `--accept` match: separators to posix, no surrounding
    slashes, lowercased.

    Extracted because the two sides had drifted: the candidate side normalized backslashes and the
    user-input side did not, so a hand-typed `--accept backend\\evals` matched nothing on Windows —
    printing "skipped", writing no config, and exiting 0 (#478 second-pass review). Same reasoning as
    `findings.py::normalize_location`: a path has to compare identically across operating systems, so
    exactly one function may decide what "the same name" means.

    Order matters. Separators are normalized BEFORE `strip("/")`, so a trailing `backend\\evals\\` is
    stripped too; doing it the other way round leaves the trailing backslash in place."""
    return s.strip().replace("\\", "/").strip("/").lower()


def _accept_keys(directory: str) -> set[str]:
    """What an `--accept` name may be written as for this candidate: the full repo-relative path
    the tool PRINTS (`backend/evals`) or the bare segment (`evals`).

    Matching used to be segment-only, while the listing and the skill both show/say the full path.
    `--accept backend/evals` therefore matched nothing, printed "skipped", wrote no config — and
    exited 0, so an agent following the skill believed it had primed the repo (#478 review)."""
    d = _norm_accept_name(directory)
    return {d, d.rsplit("/", 1)[-1]}


def _repo_directories(repo: Path) -> set[str]:
    """Every repo-relative directory in the TREE (posix, as the tree spells them): each directory
    that holds files, plus all of its ancestors.

    The advisor's `_dir_members` walks past `.gitignore` (a gitignored tree is itself a non-product
    signal), so this sees the vendored/generated dirs too. Ancestors are added because a directory
    that only holds sub-directories is still a real directory a user may name or a segment may hit."""
    from agentsec.advisor import _dir_members

    out: set[str] = set()
    for d in _dir_members(repo):
        parts = d.split("/")
        for i in range(1, len(parts) + 1):
            out.add("/".join(parts[:i]))
    return out


def _configured_segments(repo: Path) -> dict[str, tuple[str, ...]]:
    """Directory-segment name -> the `.agentsec/config.json` key(s) that already carry it.

    The KEY matters, not just the membership: `archive_paths` drops a tree, `nonproduct_paths` only
    demotes it, and `--accept` cannot express which one it wants. Reporting the tier is what keeps
    "already configured" a true statement when the name is configured in the *other* tier from the
    one the advisor would have chosen (#478 agentic gate, F3)."""
    from agentsec.config import load_repo_config

    cfg = load_repo_config(repo)
    out: dict[str, set[str]] = {}
    for key, segs in (("archive_paths", cfg.archive_segments), ("nonproduct_paths", cfg.nonproduct_segments)):
        for s in segs:
            out.setdefault(_norm_accept_name(s), set()).add(key)
    return {seg: tuple(sorted(keys)) for seg, keys in out.items()}


def _coverage_of(reldir: str, configured: dict[str, tuple[str, ...]]) -> tuple[str, ...]:
    """Why one repo directory is ALREADY non-product — the tier(s) covering it, empty if none.

    A verbatim mirror of `advisor.suggest_proactive`'s skip condition, which is the definition of
    "there is nothing left to accept here": a config segment on ANY path segment, **or** the
    hardwired Layer-1 conventions (`tests/`, `fixtures/`, `migrations/`, …) reported as `built-in`.
    Both disjuncts matter — a directory covered by either is one the advisor will never suggest
    again, so an `--accept` naming it can only ever be satisfied or permanently impossible."""
    from agentsec.guards.base import is_nonproduct_path

    tiers = {t for seg in _norm_accept_name(reldir).split("/") for t in configured.get(seg, ())}
    if is_nonproduct_path(reldir + "/_"):
        tiers.add("built-in")
    return tuple(sorted(tiers))


def _satisfied_names(repo: Path, names: set[str]) -> dict[str, str]:
    """The subset of `--accept` names whose requested state ALREADY holds -> the tier(s) holding it.
    **The one place that decides what "already satisfied" means.**

    Two conditions, and the bugs this closes are one per condition:

    1. *Coverage* mirrors `advisor.suggest_proactive` exactly, via `_coverage_of`. Testing only the
       LEAF config segment made a name the advisor refuses to re-suggest read as "never valid" and
       exit 1 with the desired state already in effect — `{"nonproduct_paths": ["backend"]}` covers
       `backend/evals` (F2), and the Layer-1 conventions cover `migrations/` with no config at all.
    2. *Existence*: the name must actually name a directory in the repo, matched by the same
       `_accept_keys` rule the candidate side uses. Without it, `already` was a bare name set with no
       relation to the tree, so `{"nonproduct_paths": true}` (a documented shorthand for 9 common
       segment names) turned `--accept docs` on a repo with no `docs/` into a free pass at rc=0 —
       the exact failure-presents-as-success shape this command's contract exists to prevent (F3).

    A name is satisfied only when EVERY directory it names is covered: `--accept evals` with
    `{"nonproduct_paths": ["backend"]}` and both a `backend/evals` and a `frontend/evals` is not
    satisfied, and must fall through to the write path that covers the second one too."""
    if not names:
        return {}          # nothing to test: skip the full repo walk below (#478 review, L3). The
                           # common all-names-matched case reaches here with an empty set, and
                           # `_repo_directories` is a whole-tree walk that then produces nothing.
    configured = _configured_segments(repo)
    dirs = _repo_directories(repo)
    out: dict[str, str] = {}
    for name in names:
        n = _norm_accept_name(name)
        named = [d for d in dirs if n in _accept_keys(d)]
        if not named:
            continue                                  # names nothing in the tree — not satisfied
        tiers: set[str] = set()
        for d in named:
            covering = _coverage_of(d, configured)
            if not covering:
                break                                 # one named dir is NOT covered — not satisfied
            tiers.update(covering)
        else:
            out[name] = "+".join(sorted(tiers))
    return out


def _print_satisfied(satisfied: dict[str, str]) -> None:
    """The single "already non-product" message per name (stdout). ONE message, not two: the tip
    announced this outcome twice, with different wording, on two different streams (#478 agentic
    gate, F6). The tier is part of the message because "nothing to do" is only a true statement
    about the config once the reader can see WHICH tier is in effect (F3). A name held by the
    built-in tier WITHOUT an archive tier gets its own wording: Layer 1 rank-demotes but never
    drops external-scanner findings, so "nothing to do" overstated it: the archive (drop) action
    is still open, and on a real repo the built-in tests tree can dominate the report totals.
    A `built-in+nonproduct_paths` combination is still demote-only (that config entry is a no-op
    for a Layer-1 tree), so it gets the honest wording too, never the pre-fix message (#716,
    #724 review)."""
    configured = {
        n: t for n, t in satisfied.items()
        if "built-in" not in t.split("+") or "archive_paths" in t.split("+")
    }
    builtin_demote_only = sorted(n for n in satisfied if n not in configured)
    if configured:
        detail = ", ".join(f"{name} ({tier})" for name, tier in sorted(configured.items()))
        print(f"Already non-product, nothing to do: {detail}")
    if builtin_demote_only:
        print(
            f"Already rank-demoted by the built-in conventions: {', '.join(builtin_demote_only)}. "
            "Scanner findings there still count toward report totals; to remove them, add the "
            "tree to archive_paths (evidence-based proposal: `agentsec audit --suggest-excludes`)."
        )


def _inherited_dirs(
    repo: Path, accepted_dirs: set[str], archive_add: tuple[str, ...], nonproduct_add: tuple[str, ...]
) -> tuple[list[str], list[str]]:
    """Directories in the REPO TREE that inherit an accepted segment name, split
    `(dropped, demoted)`. The top tree only (a nested inheritor adds nothing).

    Scanning the tree rather than this run's suggested candidates is the whole point: the directory
    that inherits an accepted segment is precisely the one the advisor did NOT suggest — a live
    `app/vendor` package or a product `frontend/evals` is import-reachable and not test-shaped, so
    `_score_dir` gives it zero robust axes and it can never be a `Candidate`. Warning only about
    fellow candidates therefore left the dangerous case structurally invisible, and for
    `archive_paths` that silence is a full DROP of a product tree's findings — a security tool
    disabling its own coverage at rc=0 with an empty stderr (#478 agentic gate, F1)."""
    archive = {s.lower() for s in archive_add}
    segments = archive | {s.lower() for s in nonproduct_add}
    if not segments:
        return [], []
    hit = sorted(
        d for d in _repo_directories(repo)
        if _candidate_segment(d).lower() in segments
        and not any(_norm_accept_name(d) == a or _norm_accept_name(d).startswith(a + "/")
                    for a in accepted_dirs)          # the accepted trees, and anything inside them
    )
    top = [d for d in hit if not any(d.startswith(other + "/") for other in hit)]
    dropped = [d for d in top if _candidate_segment(d).lower() in archive]
    demoted = [d for d in top if _candidate_segment(d).lower() not in archive]
    return dropped, demoted


def _config_snippet(cands: list[object]) -> str:
    """The ready-to-paste `.agentsec/config.json` block for the suggested candidates."""
    from agentsec.advisor import Candidate

    excl = sorted({_candidate_segment(c.directory) for c in cands if isinstance(c, Candidate) and c.kind == "exclude"})
    demo = sorted({_candidate_segment(c.directory) for c in cands if isinstance(c, Candidate) and c.kind == "demote"})
    block: dict[str, list[str]] = {}
    if excl:
        block["archive_paths"] = excl
    if demo:
        block["nonproduct_paths"] = demo
    return json.dumps(block, indent=2, ensure_ascii=False)


def _render_candidates(cands: list[object]) -> str:
    """A human 'why' table for the suggested directories (advisory)."""
    from agentsec.advisor import Candidate

    typed = [c for c in cands if isinstance(c, Candidate)]
    if not typed:
        return "No non-product directories suggested — nothing looks safe to exclude.\n"
    width = max(len(c.directory) for c in typed)
    lines = ["Suggested non-product directories (advisory — nothing changed):", ""]
    for c in typed:
        cnt = f"  [{c.finding_count} finding(s)]" if c.finding_count else ""
        lines.append(f"  {c.directory:<{width}}  {c.kind:<7} {c.confidence:<9}{cnt}")
        for s in c.signals:
            lines.append(f"  {' ' * width}    · {s}")
    return "\n".join(lines) + "\n"


def _builtin_disclosure(repo: Path) -> str | None:
    """Disclosure of the hardwired Layer-1 trees (`tests/`, `fixtures/`, `migrations/`, ...) the
    proactive advisor deliberately never suggests. Layer 1 only rank-demotes external-scanner
    findings (the DROP half is per-guard), so these trees still count toward report totals, and
    silently omitting them read as "nothing left to reduce" on a repo whose tests tree was the
    dominant noise source (851 of 866 noise-floor findings on the reference RAG-app run, #716). Trees
    already archived in config ARE dropped, so those are not disclosed."""
    from agentsec.advisor import builtin_demoted_roots
    from agentsec.config import load_repo_config

    cfg = load_repo_config(repo)
    roots = [
        r for r in builtin_demoted_roots(repo)
        if not (set(r.lower().split("/")) & cfg.archive_segments)
    ]
    if not roots:
        return None
    return (
        "Built-in demoted trees (rank-low by convention, never suggested proactively): "
        + ", ".join(roots)
        + "\n  Scanner findings under these still count toward report totals. For an evidence-based"
        "\n  archive (hard-drop) proposal, run `agentsec audit <repo> --suggest-excludes`."
    )


def _persist_excludes(repo: Path, cands: list[object], args: argparse.Namespace) -> int:
    """Consent-gated write of accepted candidates into `.agentsec/config.json`. Never auto-applies."""
    from agentsec.advisor import Candidate
    from agentsec.config import write_repo_config

    typed = [c for c in cands if isinstance(c, Candidate)]
    accept_all = getattr(args, "yes", False)
    accept_raw = getattr(args, "accept", None)
    # `--accept old,evals` is an explicit, named consent: persist ONLY those suggested dirs,
    # non-interactively, and never fall back to accept-all (an empty/typo'd set writes nothing).
    accept_names: set[str] | None = None
    # `is not None`, NOT truthiness: `--accept ""` (an unset shell variable) must stay an explicit
    # empty selection that writes nothing, not fall through to the interactive/accept-all path.
    if accept_raw is not None:
        accept_names = {_norm_accept_name(s) for s in accept_raw.split(",") if s.strip()}
    # Only the pure-interactive path needs a TTY. --accept (named subset) and --yes (accept-all) do not.
    if accept_names is None and not accept_all and not sys.stdin.isatty():
        print(
            "⚠️  Refusing to write .agentsec/config.json non-interactively. Re-run with --yes to "
            "accept all suggestions, or run interactively to choose per directory.",
            file=sys.stderr,
        )
        return 1
    accepted: list[Candidate] = []
    for c in typed:
        if accept_names is not None:
            if _accept_keys(c.directory) & accept_names:
                accepted.append(c)
            continue
        if accept_all:
            accepted.append(c)
            continue
        try:
            ans = input(f"  {c.kind} '{_candidate_segment(c.directory)}' ({c.directory})? [y/N] ").strip().lower()
        except EOFError:
            ans = ""
        if ans in ("y", "yes"):
            accepted.append(c)
    unknown: list[str] = []
    satisfied: set[str] = set()
    if accept_names is not None:
        matched: set[str] = set()
        for c in accepted:
            matched |= _accept_keys(c.directory) & accept_names
        # A name whose requested state ALREADY holds is satisfied, not unknown. `suggest_proactive`
        # drops any already-covered directory from the candidate list, so such a name can never
        # appear in `typed` — leaving `_persist_excludes` unable to tell "already true" from "never
        # valid", and reporting BOTH as a failure. Re-running the same `--accept` therefore exited 1
        # with the config exactly right, and `security-prime/SKILL.md` tells the driving agent to read
        # a non-zero exit as a failed priming run. That is this command's own
        # failure-presents-as-success bug with the sign flipped (#478 agentic gate).
        # `_satisfied_names` owns the rule for BOTH sites — see its docstring for why an inline
        # leaf-segment test was wrong in both directions.
        satisfied_tiers = _satisfied_names(repo, accept_names - matched)
        satisfied = set(satisfied_tiers)
        unknown = sorted(accept_names - matched - satisfied)
        _print_satisfied(satisfied_tiers)
        if unknown:
            print(f"Note: not among the suggested candidates, skipped: {', '.join(unknown)}", file=sys.stderr)
    if not accepted:
        if accept_names is not None and satisfied and not unknown:
            # Every requested name was already in place: the desired state holds, nothing to write.
            # `_print_satisfied` above already said so — once, on one stream.
            return 0
        print("Nothing accepted — .agentsec/config.json unchanged.")
        # A `--accept` that matched NOTHING is a failed request, not a no-op success. Exiting 0
        # let a typo'd or wrongly-formed name read as "the repo is primed" to a script or an agent
        # following the skill (#478 review). An empty `--accept ""` lands here too, deliberately.
        return 1 if accept_names is not None else 0
    archive_add = tuple(sorted({_candidate_segment(c.directory) for c in accepted if c.kind == "exclude"}))
    nonproduct_add = tuple(sorted({_candidate_segment(c.directory) for c in accepted if c.kind == "demote"}))
    # The config matches by directory-SEGMENT name, so accepting `backend/evals` also covers any
    # other `evals/` tree in the repo. Selection is per-path; the effect is per-segment. Name the
    # extra directories that inherit it rather than let a `frontend/evals` product tree be demoted —
    # or an `app/vendor` package be DROPPED — invisibly (#478 review; repo-tree scan + the lossy-tier
    # escalation per the agentic gate's F1).
    accepted_dirs = {_norm_accept_name(c.directory) for c in accepted}
    dropped, demoted = _inherited_dirs(repo, accepted_dirs, archive_add, nonproduct_add)
    if dropped:
        print(
            "⚠️  archive_paths is LOSSY and matches by directory NAME, so findings are now DROPPED "
            "in: " + ", ".join(dropped)
            + " — confirm these are non-product before you rely on the report.",
            file=sys.stderr,
        )
    if demoted:
        print(
            "Note: the config matches by directory NAME, so this also covers: " + ", ".join(demoted),
            file=sys.stderr,
        )
    try:
        changed = write_repo_config(repo, archive_add=archive_add, nonproduct_add=nonproduct_add)
    except (ValueError, OSError) as exc:
        # Malformed existing config (refused, never overwritten) or an unwritable path — report it
        # rather than raising a traceback out of the CLI (#478 review).
        print(f"⚠️  Could not write .agentsec/config.json: {exc}", file=sys.stderr)
        return 1
    print(f"Wrote {repo / '.agentsec' / 'config.json'}:")
    for key, vals in sorted(changed.items()):
        print(f"  {key}: {', '.join(vals)}")
    return 1 if unknown else 0


def _cmd_suggest_excludes(args: argparse.Namespace) -> int:
    from agentsec.advisor import Candidate, suggest_proactive
    from agentsec.detect import detect

    repo = Path(args.path)
    cands: list[object] = list(suggest_proactive(repo, detect(repo)))
    # `--accept` counts as a write request even when EMPTY (`--accept ""`), so the empty-selector
    # case reaches `_persist_excludes` and reports a failed request rather than falling through to
    # the advisory-only path and exiting 0 (#478 review).
    wants_write = bool(
        getattr(args, "write", False)
        or getattr(args, "yes", False)
        or getattr(args, "accept", None) is not None
    )
    if getattr(args, "format", "text") == "json":
        if wants_write:
            # The JSON branch returns before every write path, so `--format json --accept X` printed
            # the listing, wrote nothing and exited 0 — the same "a failed request reads as a primed
            # repo" shape the rest of this command's contract exists to prevent. `security-prime`
            # uses `--format json` to LIST (step 2) and `--accept` to WRITE (step 5); an agent that
            # combines them must be told, not silently obeyed by half (#478 agentic gate, F7).
            print(
                "⚠️  --format json is a read-only listing and cannot write .agentsec/config.json. "
                "Re-run without --format json to apply --write/--yes/--accept.",
                file=sys.stderr,
            )
            return 2
        print(json.dumps(
            [vars(c) for c in cands if isinstance(c, Candidate)], indent=2, ensure_ascii=False
        ))
        return 0
    print(_render_candidates(cands), end="")
    disclosure = _builtin_disclosure(repo)
    if disclosure:
        print()
        print(disclosure)
    if cands:
        print("\nAdd to .agentsec/config.json to apply:\n")
        print(_config_snippet(cands))
        if not wants_write:
            print(
                "\nRe-run with --write to save (interactive), --write --yes to accept all (CI), "
                "or --write --accept old,evals to save a named subset."
            )
    if cands and wants_write:
        return _persist_excludes(repo, cands, args)
    accept_raw = getattr(args, "accept", None)
    if accept_raw is not None:
        # No candidates at all. That is a failed request UNLESS every requested name is already in
        # the config: `suggest_proactive` drops already-configured directories, so a fully-primed
        # repo legitimately produces zero candidates and re-running the same `--accept` must not
        # report failure. This path bypasses `_persist_excludes`, so it needs the same
        # already-satisfied test rather than inheriting it (#478 agentic gate, B33) — routed through
        # the SAME `_satisfied_names` helper, since two inline copies of one rule is how the leaf-only
        # / tree-blind variants of F2 and F3 came to differ from `suggest_proactive` in the first place.
        wanted = {_norm_accept_name(s) for s in accept_raw.split(",") if s.strip()}
        satisfied_tiers = _satisfied_names(repo, wanted)
        outstanding = sorted(wanted - set(satisfied_tiers))
        _print_satisfied(satisfied_tiers)
        if wanted and not outstanding:
            return 0
        if outstanding:
            print(
                f"Note: not among the suggested candidates, skipped: {', '.join(outstanding)}",
                file=sys.stderr,
            )
        print("Nothing accepted — .agentsec/config.json unchanged.")
        return 1
    return 0


def _cmd_report_gap(args: argparse.Namespace) -> int:
    from agentsec.gap_report import issue_url, list_gaps, open_in_browser

    stack: str | None = getattr(args, "stack", None)
    if stack is None:
        gaps = list_gaps()
        if not gaps:
            print(
                "No gaps recorded yet. Run `agentsec detect <repo>` or `agentsec audit <repo>` "
                "on a project that uses an uncovered stack (django, flask, prisma, go)."
            )
            return 0
        print(f"Recorded gap(s) ({len(gaps)}):")
        for s, first_seen in sorted(gaps.items()):
            print(f"  {s}  (first seen {first_seen})")
        print("\nRun `agentsec report-gap <stack>` to print a pre-filled GitHub issue URL.")
        return 0

    # Default: print the URL only (no network, no browser). `--open` launches the browser.
    url = issue_url(stack)
    print(f"Report the '{stack}' stack gap by opening this pre-filled GitHub issue:")
    print(f"  {url}")
    if getattr(args, "open", False):
        open_in_browser(url)
        print("(opened in your browser)")
    return 0


def _db_target_lines(root: Path) -> list[str]:
    """Surface DB/Supabase target locality from the repo's env files (read-only,
    pure string parse — no connection). Renders host + locality only, **never** the
    secret value, so a misaimed-at-production DSN is visible at `detect` time."""
    from agentsec.detect import _walk
    from agentsec.targets import db_urls_in_env, describe

    env_names = {".env", ".env.example", ".env.sample", ".env.local"}
    blob = ""
    for f in sorted(p for p in _walk(root) if p.name in env_names):
        try:
            blob += "\n" + f.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
    return [f"  db target [{var}]: {describe(url)}" for var, url in db_urls_in_env(blob)]


def _cmd_trifecta(args: argparse.Namespace) -> int:
    from agentsec.ai.lethal_trifecta import assess, to_scaffold
    from agentsec.detect import detect

    root = Path(args.path)
    prof = detect(root)
    if "llm" not in prof.features:
        print("No LLM/agent framework detected — lethal-trifecta analysis is N/A for this stack.")
        return 0
    print(to_scaffold(assess(root, prof)))
    return 0


def _version_annotation(spec: ToolSpec | None, path: str) -> tuple[str, str]:
    """Doctor-row (glyph, suffix) for a *present* tool: installed vs pin (#592).

    Four glyphs so a glyph-scan alone stays honest: ``?`` is its own state on
    purpose — sharing ``✓`` would let a probe failure read as currency (the
    exact bug being fixed), and sharing ``⚠`` would make an unparseable-but-fine
    tool look broken. An unpinned tool that starts returns ('✓', '') so its row
    renders byte-identically to before. Advisory only: doctor's exit code stays 0.

    A python-kind tool is first run (`tool_version.liveness`, #1043): a managed
    venv whose interpreter a distro bump repointed leaves every console script
    present but dead, and presence alone used to render that as ``✓``.
    """
    from agentsec import tool_version

    if spec is not None and tool_version.checks_liveness(spec):
        alive = tool_version.liveness(spec, path)
        argv = " ".join([spec.binary, *spec.liveness_args])
        if alive == "broken":
            if tool_version.is_managed(path):
                return "✗", f" broken — `{argv}` failed; run `agentsec setup <repo>` to rebuild the managed venv"
            return "✗", (
                f" broken — `{argv}` failed; {path} is not agentsec-installed, "
                f"so setup will not replace it — fix it or remove it from PATH"
            )
        if alive == "unknown":
            return "?", f" could not verify it starts (`{argv}` gave no answer)"
    if spec is None or not spec.pin_name:
        return "✓", ""
    tv = tool_version.probe(spec, path)
    if tv.state == "current":
        return "✓", f" {tv.installed}"
    if tv.state == "ahead":
        return "✓", f" {tv.installed} (pinned {tv.pinned})"
    if tv.state == "stale":
        if tool_version.is_managed(path):
            return "⚠", f" {tv.installed} (pinned {tv.pinned} — stale; run `agentsec setup <repo>` to upgrade)"
        return "⚠", (
            f" {tv.installed} (pinned {tv.pinned} — stale; {path} is not agentsec-installed, "
            f"so setup will not replace it — upgrade it or remove it from PATH)"
        )
    if tv.state == "unknown":
        return "?", f" version unknown (pinned {tv.pinned} — could not verify)"
    return "✓", ""  # defensive: no-pin/absent are handled above / by the caller


def _cmd_doctor(args: argparse.Namespace) -> int:
    """Report which external scanners / live-scan prerequisites are installed."""
    if getattr(args, "canary", False):
        from agentsec.canary import run_canary, to_text

        report = run_canary()
        print(to_text(report))
        return 0 if report.ok else 1

    if getattr(args, "efficacy", None) is not None:
        repo = Path(args.efficacy or ".")
        result = run_audit(repo, run_scanners=False, exceptions_path=Path(os.devnull))
        from agentsec.registry import ALL_GUARDS

        fired: dict[str, int] = {}
        for f in result.findings:
            fired[f.check_id] = fired.get(f.check_id, 0) + 1
        ran_ids = set(result.ran)
        # #895 (same coverage-honesty shape as the audit footer): a guard that CRASHED is in
        # `ran` with 0 findings, so without this it reads as "silent" — indistinguishable from
        # a clean run that found nothing. Give it its own status so a partially-blind dashboard
        # can't present as a clean one.
        errored_ids = set(result.tools_errored)
        print(f"Guard efficacy dashboard — {repo}\n")
        print(f"  {'guard':<40} {'status':<10} {'findings'}")
        print(f"  {'-'*40} {'-'*10} {'-'*8}")
        for g in sorted(ALL_GUARDS, key=lambda x: x.id):
            if g.id not in ran_ids:
                status = "N/A"
                count = "-"
            elif fired.get(g.id, 0) > 0:
                status = "FIRED"
                count = str(fired[g.id])
            elif g.id in errored_ids:
                status = "errored"
                count = "-"
            else:
                status = "silent"
                count = "0"
            print(f"  {g.id:<40} {status:<10} {count}")
        total_fired = sum(1 for g in ALL_GUARDS if fired.get(g.id, 0) > 0)
        total_ran = len(ran_ids)
        print(f"\n  {total_fired}/{total_ran} guards fired at least once against this repo.")
        n_errored = sum(
            1 for g in ALL_GUARDS if g.id in errored_ids and fired.get(g.id, 0) == 0
        )
        if n_errored:
            # Don't let the "X/Y fired" headline read as a clean sweep when some guards never
            # got a fair run — Y counts them as "ran" but they errored (see the table above).
            print(
                f"  ⚠ {n_errored} guard(s) errored (shown above) — not a clean 'silent'; "
                "their result is unknown."
            )
        return 0

    if getattr(args, "sandbox", False):
        from agentsec.guard_sandbox import scan_guards
        from agentsec.guard_sandbox import to_text as sandbox_to_text

        sandbox_report = scan_guards()
        print(sandbox_to_text(sandbox_report))
        return 0 if sandbox_report.ok else 1

    if getattr(args, "clean_canary", False):
        from agentsec.clean_canary import run_clean_canary
        from agentsec.clean_canary import to_text as clean_to_text

        clean_report = run_clean_canary()
        print(clean_to_text(clean_report))
        return 0 if clean_report.ok else 1

    if getattr(args, "check_updates", False):
        from datetime import UTC, datetime

        from agentsec import net, update_check
        from agentsec.config import load_repo_config

        cli_tier = getattr(args, "network", None) or "tier1"
        tier = net.resolve_tier(config_tier=load_repo_config(Path()).network_tier, cli=cli_tier)
        manifest = net.Manifest(tier=tier)
        if tier < 1:
            print("note: --check-updates needs network tier 1, but the active tier is 0 "
                  "(DO_NOT_TRACK?) — skipped.", file=sys.stderr)
            return 0
        update_result = update_check.check_updates(
            tier=tier, now=datetime.now(UTC), manifest=manifest,
            refresh=getattr(args, "refresh", False),
        )
        print(manifest.render(), file=sys.stderr)
        print(update_check.to_text(update_result))
        return 0

    from agentsec.registry import ALL_RUNNERS
    from agentsec.runners.base import which
    from agentsec.tooling import TOOLS

    print("agentsec doctor — external tool availability\n")
    print(_registry_stamp(markdown=False) + "\n")
    missing_pipx: list[str] = []
    broken = 0  # present but cannot start (#1043) — the only `✗` on a present tool

    print("Deterministic scanners (used by `agentsec audit`):")
    spec_by_runner = {t.runner_id: t for t in TOOLS if t.runner_id}
    for r in sorted(ALL_RUNNERS, key=lambda x: x.id):
        # A binary-less runner (r.binary == "") wraps no external tool — it's always
        # available, and `which("")` would misreport it as missing (go_osv_hygiene.py).
        if not r.binary:
            print(f"  ✓ {r.id:<11} (no external binary — network only)")
            continue
        path = which(r.binary)
        if path is None:
            print(f"  ✗ {r.id:<11} ({r.binary})  → {r.install_hint}")
            if r.install_hint.startswith("pipx install"):
                missing_pipx.append(r.install_hint.split()[-1])
            continue
        glyph, suffix = _version_annotation(spec_by_runner.get(r.id), path)
        if glyph == "✗":
            broken += 1
        print(f"  {glyph} {r.id:<11} ({r.binary}){suffix}")

    print("\nLive scanners (used by `agentsec live`):")
    for t in [t for t in TOOLS if t.doctor_group == "live"]:
        path = which(t.binary)
        if path is None:
            print(f"  ✗ {t.binary:<11} {t.doctor_label}  → {t.guided_hint}")
            continue
        glyph, suffix = _version_annotation(t, path)
        if glyph == "✗":
            broken += 1
        print(f"  {glyph} {t.binary:<11} {t.doctor_label}{suffix}")

    if missing_pipx:
        print(
            "\nInstall the missing pipx-able scanners in one go:\n"
            f"  pipx install {' '.join(sorted(set(missing_pipx)))}"
        )
    else:
        print("\nAll pipx-installable scanners present.")
    if broken:
        # Present is not usable (#1043): an audit reports these scanners as errored and
        # loses their findings, so say it once where a skimming reader will see it.
        print(f"⚠ {broken} installed tool(s) cannot start — see the ✗ broken rows above.")
    print("\nTip: `agentsec setup <repo>` installs the applicable tools for you (no PATH edits needed).")
    return 0


def _cmd_setup(args: argparse.Namespace) -> int:
    """Install the applicable scanner toolchain into the agentsec-managed dir."""
    from agentsec.setup import setup

    repo = Path(args.path)
    result = setup(
        repo,
        dry_run=args.dry_run,
        include_all=args.all,
        include_live=args.include_live,
        upgrade=not args.no_upgrade,
        force=args.force,
    )
    print(result.render())
    if getattr(args, "suggest_excludes", False):
        from agentsec.advisor import suggest_proactive
        from agentsec.detect import detect
        cands: list[object] = list(suggest_proactive(repo, detect(repo)))
        print()
        print(_render_candidates(cands), end="")
        disclosure = _builtin_disclosure(repo)
        if disclosure:
            print()
            print(disclosure)
        if cands:
            print("\nApply with `agentsec suggest-excludes --write` (advisory; writes nothing here).")
    return 0  # informational: exit 0 even when some tools are guided/skipped


def _cmd_ci_list(args: argparse.Namespace) -> int:
    """List CI components and whether each applies to the detected stack."""
    from agentsec.ci.library import load_components
    from agentsec.detect import detect

    prof = detect(Path(args.path))
    print(f"CI components for {prof.root} ({prof.summary()}):\n")
    for c in load_components():
        mark = "✓" if c.applies(prof) else "–"
        secrets = ", ".join(c.requires_secrets) or "none"
        print(f"  {mark} {c.id:<16} {c.summary}")
        print(f"      category={c.category}  secrets={secrets}")
    print("\n  ✓ = applies to this stack, – = N/A. Add one with `agentsec ci add <id>`.")
    return 0


def _cmd_ci_show(args: argparse.Namespace) -> int:
    """Show a component's manifest + the files it would write."""
    from agentsec.ci.library import derive_params, get_component, planned_files
    from agentsec.detect import detect

    try:
        c = get_component(args.component)
    except ValueError as e:
        print(str(e), file=sys.stderr)
        return 2
    prof = detect(Path(args.path))
    params = derive_params(c, prof)
    print(f"{c.id} — {c.title}")
    print(f"  category:   {c.category}")
    print(f"  summary:    {c.summary}")
    print(f"  applies:    {c.applies(prof)} (needs features: {sorted(c.applies_when) or 'any'})")
    print(f"  secrets:    {', '.join(c.requires_secrets) or 'none'}")
    if c.notes:
        print(f"  notes:      {c.notes}")
    print("  writes:")
    for f in planned_files(c, params):
        print(f"    - {f}")
    return 0


def _cmd_ci_doctor(args: argparse.Namespace) -> int:
    """Static preflight of the generated agentsec CI workflows. Exits 1 on any error."""
    from agentsec.ci.doctor import diagnose, has_errors, render

    diags = diagnose(Path(args.path))
    print(render(diags), end="")
    return 1 if has_errors(diags) else 0


def _confirm_baseline(findings: list[Finding], *, accept_all: bool) -> bool:
    """Surface what a `--with-baseline` snapshot is about to record, before it is written.

    The ratchet baseline does NOT suppress findings — every finding stays visible in the
    report each run; the snapshot only excludes them from the gate's `--fail-on` exit, so
    only findings NEW since the snapshot fail CI. Still, choosing not to *gate* on an existing
    HIGH/CRITICAL on day one should be a conscious choice. So: always print the severity
    breakdown, and when any HIGH/CRITICAL is present require confirmation (an interactive
    `[y/N]`, or `--yes` for CI). No HIGH/CRITICAL → print + proceed."""
    counts = collections.Counter(f.severity for f in findings)
    order = sorted(counts, key=lambda s: SEVERITY_RANK.get(s, 99))
    summary = ", ".join(f"{counts[s]} {s.upper()}" for s in order) or "0"
    print(f"  Baseline will record {len(findings)} finding(s) as the accepted starting posture: {summary}")
    blocking = [f for f in findings if f.severity in ("critical", "high")]
    if not blocking or accept_all:
        return True
    print(f"  ⚠️  {len(blocking)} HIGH/CRITICAL finding(s) will be visible but NON-GATING from day one "
          "(still shown every run; only NEW findings fail the gate):", file=sys.stderr)
    for f in blocking[:20]:
        print(f"      {f.severity.upper():8} {f.rule or f.check_id}  {f.location}", file=sys.stderr)
    if len(blocking) > 20:
        print(f"      … and {len(blocking) - 20} more", file=sys.stderr)
    if not sys.stdin.isatty():
        print("  Refusing to baseline HIGH/CRITICAL findings non-interactively. Review them, fix what "
              "you can, then re-run with --yes to accept the rest into the (non-gating) baseline.",
              file=sys.stderr)
        return False
    return input("  Record these as the non-gating baseline? [y/N] ").strip().lower() in ("y", "yes")


def _cmd_ci_add(args: argparse.Namespace) -> int:
    """Adapt + install one or more components' files into the target repo.

    Accepts `<component...> [path]`: the trailing token is the repo path when it
    isn't a known component id, so `ci add <comp> <path>` still works while
    `ci add <comp> <comp> ...` installs several at once (one shell-agnostic
    call, no bash needed)."""
    from agentsec.ci.library import (
        ActionPinError,
        _agentsec_ref,
        get_component,
        install,
        load_components,
        needs_action_sha,
        resolve_action_sha,
        would_write,
    )
    from agentsec.detect import detect

    items = list(args.components)
    known = {c.id for c in load_components()}
    if len(items) > 1 and items[-1] not in known:
        path_str, component_ids = items[-1], items[:-1]
    else:
        path_str, component_ids = ".", items

    # Resolve every id first so a typo fails fast before anything is written.
    components = []
    for cid in component_ids:
        try:
            components.append(get_component(cid))
        except ValueError as e:
            print(str(e), file=sys.stderr)
            return 2
    # Only self-audit consumes --advisory; elsewhere it would be a silent no-op that writes a
    # BLOCKING gate the user believes is non-blocking, so refuse before writing anything.
    ignored = [c.id for c in components if c.id != "self-audit"]
    if args.advisory and ignored:
        print(f"--advisory applies to self-audit only; it would be ignored for: {', '.join(ignored)}. "
              "Install those components in a separate `ci add` without --advisory.", file=sys.stderr)
        return 2
    # The action pin, resolved ONCE and before anything is written, so an offline or
    # unauthorised lookup fails the whole call instead of leaving a half-installed set.
    pinning = [c for c in components if needs_action_sha(c)]
    action_sha = args.action_sha.strip().lower()
    if args.action_sha and not pinning:
        print("--action-sha applies to self-audit only; nothing here pins agentsec's action.",
              file=sys.stderr)
        return 2
    if action_sha and not re.fullmatch(r"[0-9a-f]{40}", action_sha):
        print(f"--action-sha must be a full 40-hex commit SHA, got: {args.action_sha}", file=sys.stderr)
        return 2
    # --path lands in YAML scalars of the self-audit workflow; quoting carries a `'`, but no
    # quoting carries a line break, so refuse control characters before anything is written.
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in args.path):
        print(f"--path must not contain control characters (a line break, a tab, ...), got: {args.path!r}",
              file=sys.stderr)
        return 2

    root = Path(path_str)
    prof = detect(root)
    # Look the pin up only when a pinning component will actually write: not one skipped as N/A
    # for this stack, not one whose files all exist without --force, never on a dry run. The
    # lookup is egress; spending it (and possibly failing offline) on a no-op is noise.
    lookup = [
        c for c in pinning
        if (c.applies(prof) or args.force)
        and would_write(c, prof, root, force=args.force, audit_path=args.path)
    ]
    if lookup and not action_sha and not args.dry_run:
        # The lookup is egress, so it follows the policy of the other inherently networked
        # commands (corpus-scan): invoking it implies tier 1, it is disclosed before it runs,
        # and DO_NOT_TRACK=1 forces tier 0, which refuses it. It sends nothing about the repo.
        from agentsec import AGENTSEC_REPO_URL, net
        if net.resolve_tier(cli="tier1") < 1:
            print("ci add self-audit looks up agentsec's release commit with `git ls-remote`, and the "
                  "active network tier is 0 (DO_NOT_TRACK=1). Pass `--action-sha <40-hex commit SHA "
                  f"of {_agentsec_ref()}>` to pin it without the lookup.", file=sys.stderr)
            return 2
        print(f"agentsec network: git ls-remote → {AGENTSEC_REPO_URL}  sends: nothing about your repo "
              f"(asks for the {_agentsec_ref()} tag)  [tier 1]", file=sys.stderr)
        try:
            action_sha = resolve_action_sha(_agentsec_ref())
        except ActionPinError as e:
            print(f"Could not pin agentsec's action: {e}", file=sys.stderr)
            return 2
        print(f"Pinned agentsec's action to {action_sha} ({_agentsec_ref()}).")

    verb = "Would write" if args.dry_run else "Wrote"
    multi = len(components) > 1
    rc = 0
    secrets: list[tuple[str, str]] = []

    for c in components:
        if multi:
            print(f"\n=== {c.id} ===")
        if not c.applies(prof) and not args.force:
            print(
                f"'{c.id}' is N/A for this stack (needs features: {sorted(c.applies_when)}; "
                f"detected: {sorted(prof.features)}). Re-run with --force to install anyway.",
                file=sys.stderr,
            )
            rc = rc or 1
            continue

        results = install(
            c, prof, root, force=args.force, dry_run=args.dry_run,
            audit_path=args.path, with_baseline=args.with_baseline,
            install_secret=args.install_secret, advisory=args.advisory, action_sha=action_sha,
        )
        conflicts = [r for r in results if r.action == "skip-exists"]
        for r in results:
            rel = r.target.relative_to(root)
            if r.action == "skip-exists":
                print(f"  ! exists, skipped (use --force): {rel}")
            else:
                print(f"  {verb}: {rel}")
        if conflicts and not args.dry_run:
            print(
                f"\n{len(conflicts)} file(s) already existed and were left untouched. "
                "Re-run with --force to overwrite.",
                file=sys.stderr,
            )
            rc = rc or 1
        # --with-baseline: record current findings as a ratchet snapshot using the SAME flags
        # the gate runs (deterministic, scoped to --path) so fingerprints match. The gate keeps
        # every finding VISIBLE in the report and fails only on findings NEW since this snapshot
        # (the drift model) — it does NOT suppress existing findings the way an exception registry
        # would, so a day-one install can't create a hidden blind spot.
        if c.id == "self-audit" and args.with_baseline and not args.dry_run:
            from agentsec.ci.library import baseline_rel
            from agentsec.drift import save_snapshot
            bl_path = root / baseline_rel(args.path)
            raw = run_audit(root / args.path if args.path != "." else root,
                            run_scanners=True, exceptions_path=Path(os.devnull),
                            deterministic=True)
            if not _confirm_baseline(raw.findings, accept_all=args.yes):
                print("  Skipped baseline — the gate is wired to expect one. Resolve the findings, or "
                      "re-run `ci add self-audit --with-baseline --yes` to accept them.", file=sys.stderr)
                rc = rc or 1
            else:
                n = save_snapshot(raw.findings, bl_path)
                print(f"  Recorded ratchet baseline: {n} finding(s) as the accepted starting posture "
                      f"(still shown every run; only NEW findings fail the gate): "
                      f"{bl_path.relative_to(root)}")

        secrets += [(c.id, s) for s in c.requires_secrets]

    if args.install_secret:
        secrets.insert(0, ("private install", args.install_secret))

    if secrets:
        print("\nConfigure these GitHub repo secrets (Settings → Secrets and variables → Actions):")
        for cid, s in secrets:
            print(f"  - {s}" + (f"  ({cid})" if multi else ""))
    else:
        print("\nNo secrets required.")
    print(
        "No secrets or project-specific URLs are embedded in the generated files; "
        "configure any secrets above yourself. Review the changes — nothing was committed."
    )
    return rc


def _cmd_python_harden(args: argparse.Namespace) -> int:
    """Deterministically harden a project's Python (uv) dependency config."""
    from agentsec.python_harden import harden, render_summary

    result = harden(
        Path(args.path),
        cooldown_hours=args.cooldown,
        run_lock=not args.no_lock,
        scaffold_exceptions=args.scaffold_exceptions,
        dry_run=args.dry_run,
    )
    print(render_summary(result, dry_run=args.dry_run))
    return 0 if result.ok else 1


def _cmd_js_harden(args: argparse.Namespace) -> int:
    """Deterministically harden a project's JS/TS (npm/pnpm) dependency config."""
    from agentsec.js_harden import harden, render_summary

    result = harden(
        Path(args.path),
        cooldown_hours=args.cooldown,
        scaffold_allowlist=not args.no_allowlist,
        dry_run=args.dry_run,
    )
    print(render_summary(result, dry_run=args.dry_run))
    return 0 if result.ok else 1


def _changed_files_from_git(repo: Path, ref: str) -> frozenset[str] | None:
    """Return repo-relative forward-slash paths changed since `ref` via git.

    Returns None on any git error (missing binary, not a repo, etc.) so callers
    can warn and fall through to a full scan rather than silently bailing."""
    import subprocess  # nosec B404

    if ref.startswith("-"):
        # Refuse an option-like ref (e.g. `--output=FILE`): git would parse it as an option,
        # not a revision (git-option injection). Fall through to a full scan.
        return None

    try:
        out = subprocess.run(  # nosec B603 B607
            ["git", "diff", "--name-only", ref],
            capture_output=True, text=True, cwd=str(repo), timeout=15,
        )
        if out.returncode != 0:
            return None
        paths = {p.strip().replace("\\", "/") for p in out.stdout.splitlines() if p.strip()}
        # Also add staged + untracked (new, unstaged) files for the default HEAD case — a
        # `git diff HEAD` reports neither, so a brand-new vulnerable file would be invisible.
        if ref.upper() == "HEAD":
            for extra in (["diff", "--name-only", "--cached"],
                          ["ls-files", "--others", "--exclude-standard"]):
                ex = subprocess.run(  # nosec B603 B607
                    ["git", *extra], capture_output=True, text=True, cwd=str(repo), timeout=15,
                )
                if ex.returncode == 0:
                    paths |= {p.strip().replace("\\", "/") for p in ex.stdout.splitlines() if p.strip()}
        return frozenset(paths) if paths else frozenset()
    except Exception:
        return None


def _cmd_drift(args: argparse.Namespace) -> int:
    """Compare current audit findings against a saved snapshot."""
    from agentsec.drift import DEFAULT_SNAPSHOT, diff_snapshot, read_snapshot, save_snapshot, to_markdown

    repo = Path(args.path)
    snapshot_path = Path(args.snapshot) if args.snapshot else repo / DEFAULT_SNAPSHOT

    if args.save:
        result = run_audit(repo, run_scanners=not args.guards_only,
                           exceptions_path=Path(os.devnull))
        n = save_snapshot(result.findings, snapshot_path)
        print(f"Saved snapshot: {n} finding(s) → {snapshot_path}")
        return 0

    snapshot = read_snapshot(snapshot_path)
    result = run_audit(repo, run_scanners=not args.guards_only,
                       exceptions_path=Path(os.devnull))
    diff = diff_snapshot(result.findings, snapshot)

    report = to_markdown(diff, snapshot_path)
    if args.out:
        Path(args.out).write_text(report, encoding="utf-8")
        print(f"Wrote drift report → {args.out}")
    else:
        print(report)

    # Exit 1 when regressions exist (CI-usable). Superseded (historical) SQL findings are listed
    # but non-gating here too — `DriftResult.gating_new` applies the same `is_historical` exclusion
    # as `_gating()` (#829 review: `drift` was a fourth gate site that disagreed with `audit`).
    # `DriftResult.gating` adds the reactivated findings: superseded in the snapshot, live now, so
    # `audit` fails on them while their fingerprint is unchanged (#853).
    return 1 if diff.gating and not args.no_fail else 0


def _cmd_fix(args: argparse.Namespace) -> int:
    """Deterministically apply (or preview) the allowlisted mechanical fixes."""
    from agentsec.fix import fix, render_summary

    result = fix(Path(args.path), write=args.write, rules=args.fix or None)
    print(render_summary(result, write=args.write))
    return 0 if result.ok else 1


def _ingest_findings(specs: list[str] | None) -> list[Finding]:
    from agentsec.ingest import ingest_file

    out: list[Finding] = []
    for spec in specs or []:
        kind, _, p = spec.partition("=")
        if not p:
            raise SystemExit(f"--ingest expects KIND=PATH, got '{spec}'")
        out.extend(ingest_file(kind.strip(), Path(p.strip())))
    return out


def _meta_lines(result: AuditResult, extra_meta: list[str]) -> list[str]:
    """The report's footer lines (stack, what-ran, N/A-skipped, suppressed, lapsed).

    Honest-coverage critical: this footer (esp. 'Skipped (N/A for this stack)' and the
    lapsed-exception reminders) must travel with every rendering, including the
    one-run-all artifacts and `agentsec scan` — absence of a finding is never proof of
    safety."""
    from agentsec.registry import is_baseline_guard

    base_n = sum(1 for f in result.findings if is_baseline_guard(f.check_id))
    stack_n = len(result.findings) - base_n
    meta = [
        "",
        f"_Stack:_ {result.profile.summary()}",
        f"_Baseline floor (every app):_ {base_n} issue(s)  ·  _Your stack:_ {stack_n} issue(s)",
        f"_Checks run:_ {', '.join(result.checks_run_clean) or 'none'}",
        f"_Skipped (N/A for this stack):_ {', '.join(result.skipped) or 'none'}",
    ]
    for stack in sorted(result.profile.uncovered_stacks):
        meta.append(
            f"_No dedicated guard suite yet:_ {stack} — run `agentsec report-gap {stack}` to flag this"
        )
    for lang in sorted(result.profile.foreign_languages):
        meta.append(
            f"_Unscanned language:_ {lang} — agentsec does not audit {lang}, "
            f"findings above do not cover it"
        )
    for stack in sorted(result.profile.unconfirmed_stacks):
        meta.append(
            f"_Mentioned but not confirmed:_ {stack} — the repo names it, but detection found no "
            f"conclusive usage, so {stack}-specific checks were skipped. If this repo does use "
            f"{stack}, those checks did NOT run and the result above is not a pass for them"
        )
    for artifact in sorted(result.profile.foreign_artifacts):
        meta.append(
            f"_Artifact-layer language evidence:_ {artifact} — found in a Docker base image, not "
            f"repo source; agentsec's source-only detection cannot see this language at all, so "
            f"nothing above covers it"
        )
    if result.tools_unavailable:
        meta.append(f"_Scanners not installed (skipped):_ {', '.join(result.tools_unavailable)}")
    if result.tools_offline_skipped:
        meta.append(
            "_Scanners skipped (offline — raise `--network` to enable):_ "
            f"{', '.join(result.tools_offline_skipped)}"
        )
    for note in result.tools_reduced:
        # #434: a runner that RAN with a reduced rule set is listed plainly under
        # "Checks run" — without this line the report is indistinguishable from a
        # full-coverage run even though real detections are missing.
        meta.append(f"_⚠ Reduced coverage:_ {note}")
    if result.tools_errored:
        meta.append(f"_Scanners that errored:_ {', '.join(result.tools_errored)}")
    if (unparsed := result.unparsed_python_notice()) is not None:
        # #1001: a file the AST-based checks could not parse used to read exactly like a clean one.
        meta.append(f"_⚠ {unparsed[0]}:_ {unparsed[1]}")
    if result.guards_budget_exceeded:
        # #677: harder than every disclosure above — these guards were KILLED mid-run, so
        # their checks did not complete and the gate fails unconditionally (see _gate).
        meta.append(
            "_⚠ Guards killed over their time budget (their checks did NOT complete):_ "
            f"{', '.join(result.guards_budget_exceeded)}"
        )
    if result.guards_unbudgeted:
        # #677 fallback: the worker child failed to start, so guards ran in-process with no
        # time budget — coverage is complete, the hang protection lapsed. Disclose it: a
        # silent lapse is exactly how the 2026-09-07 Windows CI wedge presented as nothing.
        meta.append(
            "_⚠ Guard time budget disabled (worker failed to start; the remaining guards ran "
            "in-process, unbudgeted)_"
        )
    meta.extend(extra_meta)
    if result.archive_excluded:
        trees = ", ".join(sorted(result.profile.archive_segments))
        meta.append(
            f"_Excluded as archived (.agentsec/config.json: {trees}):_ "
            f"{len(result.archive_excluded)} finding(s)"
        )
    if result.excluded:
        meta.append(f"_Excluded by --exclude (out of scope):_ {len(result.excluded)} finding(s)")
    n_superseded = sum(1 for f in result.findings if is_historical(f))
    if n_superseded:
        # Name the dump rather than claim "a later migration" replaced these (#1037): the dump's
        # authority over its subtree is what the schema-state pass actually established.
        dumps = ", ".join(f"`{d}`" for d in governing_dumps(result.findings)) or "a schema dump"
        meta.append(
            f"_History governed by the schema dump {dumps} (non-gating and demoted, never dropped):_ "
            f"{n_superseded} finding(s)"
        )
    prov = collections.Counter(f.provenance for f in result.findings if f.provenance)
    if prov or result.crosscheck_deduped:
        confirmed = prov.get("confirmed-live", 0)
        live_only = prov.get("splinter-only", 0)
        objs = result.crosscheck_splinter_objects
        # show distinct-object count when the raw count is inflated by per-policy/role granularity
        live_only_str = f"{live_only} live-only" + (f" ({objs} distinct objects)" if objs and objs < live_only else "")
        meta.append(
            f"_Live cross-check (Splinter):_ {confirmed} confirmed live"
            f"{f' (+{result.crosscheck_deduped} duplicate folded)' if result.crosscheck_deduped else ''}"
            f" · {prov.get('static-only', 0)} static-only · {live_only_str}"
        )
    if result.suppressed:
        meta.append(f"_Accepted via exceptions (suppressed):_ {len(result.suppressed)}")
    # A bare total hides HOW the suppression was distributed: one waiver covering 485
    # findings rendered exactly like 485 waivers covering one each (#507). Name the broad ones.
    for broad in result.broad_waivers:
        meta.append(f"_Broad waiver:_ {broad}")
    # The other half of the same honesty: the total above counts the waivers that WORKED,
    # never the ones the user is carrying, so a waiver whose finding was fixed at source
    # goes dead in silence and the gap between the two numbers is the signal (#730).
    for unused in result.unused_waivers:
        meta.append(f"_Unused waiver:_ {unused}")
    # A dead waiver whose finding is still right there under a new fingerprint (a reworded
    # message) gets its own label: "unused" would invite deleting a live accepted-risk
    # record, the opposite of the re-triage the line asks for (#896).
    for drifted in result.drifted_waivers:
        meta.append(f"_Drifted waiver:_ {drifted}")
    if result.local_suppressed:
        meta.append(
            f"_Locally suppressed (.agentsec/suppress.json):_ {len(result.local_suppressed)}"
        )
    for note in result.lapsed:
        meta.append(f"_⚠ {note}_")
    meta.append("")
    return meta


def _render_markdown(result: AuditResult, meta: list[str], top: int | None = None) -> str:
    """The full technical markdown report (findings + footer). `top` caps the detail
    list (the Summary-by-check table keeps the full tally — no silent truncation)."""
    return to_markdown(result.findings, top=top) + "\n" + "\n".join(meta)


def _gating(findings: list[Finding], gate_exclude: frozenset[str] = frozenset()) -> list[Finding]:
    """The findings the `--fail-on` gate counts — the ONE definition, shared by every severity gate
    (`_gate`, `_emit`, `harden-host`) so they cannot drift. `agentsec drift` gates by fingerprint,
    not severity, so it cannot call this; it applies the same superseded exclusion through
    `DriftResult.gating`. Every finding stays in the rendered report; two classes are visible
    but non-gating, and the CI line discloses each count:

    - fingerprints recorded in a `--baseline-snapshot` (the ratchet model: only NEW findings gate).
      A row saved as superseded history is not in `gate_exclude` (#853): it was accepted as
      answered by the dump, so once the dump stops answering it the finding gates like any other;
    - superseded (historical) SQL findings — stamped by the schema-state pass and not confirmed
      live by Splinter (`findings.is_historical`). The authoritative dump carries anything still
      live at full priority, so the migration copy is a duplicate or history. Before #800 the
      stamp was rank-only and 138 superseded HIGHs failed the flagship gate the dump had answered."""
    return [
        f for f in findings
        if not is_historical(f) and (not gate_exclude or f.fingerprint() not in gate_exclude)
    ]


def _gate(result: AuditResult, fail_on: str, no_fail: bool) -> int:
    """The CI exit code: non-zero when any gating finding (`_gating`) meets `--fail-on` (unless
    --no-fail).

    A guard killed over its time budget (#677) also fails the gate, independent of
    `--fail-on`: its checks did not complete, so the scan is partial in a way no finding's
    severity can express — passing it would be the "failure that presents as success" the
    budget exists to prevent. `--no-fail` still wins (report-only mode stays report-only)."""
    fail_rank = SEVERITY_RANK[fail_on]
    triggered = (
        any(SEVERITY_RANK[f.severity] <= fail_rank for f in _gating(result.findings))
        or bool(result.guards_budget_exceeded)
    )
    return 1 if (triggered and not no_fail) else 0


def _repo_relative_prefix(scan_path: str) -> str:
    """The scan root's POSIX path relative to the current directory, for `to_sarif`'s
    `uri_prefix`: `services/api` for `agentsec audit services/api` run from the checkout root.

    "" (no prefix, today's output) when the scan root IS the current directory, or lies outside
    it: a root elsewhere on disk has no repo-relative spelling, and guessing one would point
    code scanning at a file that does not exist. CI runs every step from the checkout root
    (`$GITHUB_WORKSPACE`), which is what makes the current directory the right anchor."""
    try:
        rel = Path(scan_path).resolve().relative_to(Path.cwd().resolve())
    except (ValueError, OSError):
        return ""
    posix = rel.as_posix()
    return "" if posix in ("", ".") else posix


def _emit(result: AuditResult, args: argparse.Namespace, extra_meta: list[str],
          gate_exclude: frozenset[str] = frozenset()) -> int:
    """Render an AuditResult (markdown / summary / SARIF), write/print it, return the CI
    gate. One `run_audit()` can feed several artifacts: the `--format` view goes to
    `--out`/stdout, and `--sarif-out PATH` additionally writes SARIF (so a single run
    yields both a human report and a code-scanning upload).

    `gate_exclude` is the set of finding fingerprints a `--baseline-snapshot` recorded as live
    (`_baseline_gate_exclude`): they remain in the rendered report (visible) but are excluded
    from the `--fail-on` exit, so the gate fails only on findings NEW since the snapshot (the
    ratchet model)."""
    meta = _meta_lines(result, extra_meta)
    full = _render_markdown(result, meta, top=getattr(args, "top", None))

    # The coverage disclosure travels with EVERY emitter, not just the markdown footer:
    # `--format sarif` suppresses the footer below, so without this a CI consumer (the
    # documented SARIF path) would never learn the scan ran degraded (#434).
    notices = result.coverage_notices()
    # Locations are scan-root-relative; code scanning and annotations resolve against the
    # checkout. Computed once so the SARIF and the annotations agree on every path.
    uri_prefix = _repo_relative_prefix(getattr(args, "path", "."))

    if args.format == "sarif":
        out = to_sarif_json(result.findings, notifications=notices,
                            budget_exceeded=result.guards_budget_exceeded, uri_prefix=uri_prefix)
    elif args.format == "summary":
        # plain-English view for non-technical readers, with the technical markdown
        # appended underneath so an engineer can still get file:line + rule.
        out = (
            to_human_summary(result.findings)
            + "\n---\n\n## Technical detail (file, line, rule)\n\n"
            + full
        )
    else:
        out = full
    if args.out:
        Path(args.out).write_text(out, encoding="utf-8")
        print(f"Wrote {args.format} report → {args.out}")
        if args.format != "sarif":
            print("\n".join(meta))
    else:
        print(out)

    # `--sarif-out` is orthogonal to `--format`: always also emit SARIF when asked, so
    # one audit produces both the chosen human view and a machine-readable artifact.
    sarif_out = getattr(args, "sarif_out", None)
    if sarif_out and args.format != "sarif":
        Path(sarif_out).write_text(
            to_sarif_json(result.findings, notifications=notices,
                          budget_exceeded=result.guards_budget_exceeded, uri_prefix=uri_prefix),
            encoding="utf-8",
        )
        print(f"Wrote sarif report → {sarif_out}", file=sys.stderr)

    # Ratchet gate: every finding stays in the report above, but those recorded in a
    # --baseline-snapshot are the accepted starting posture and don't fail the gate — only
    # findings new since the snapshot do. gate_exclude is empty unless --baseline-snapshot is set.
    # Superseded (historical) SQL findings are the other visible-but-non-gating class (#800) —
    # both live in `_gating`, the one gate set every site shares.
    fail_rank = SEVERITY_RANK[args.fail_on]
    gated = _gating(result.findings, gate_exclude)
    n_superseded = sum(1 for f in result.findings if is_historical(f))
    # #677: a budget-killed guard fails the gate regardless of finding severities — and it
    # can never be ratcheted away, because it is a state, not a finding with a fingerprint.
    triggered = (
        any(SEVERITY_RANK[f.severity] <= fail_rank for f in gated)
        or bool(result.guards_budget_exceeded)
    )
    n_annotate = getattr(args, "annotations", None)
    if n_annotate:
        # GitHub Actions reads workflow commands from the step's output. They are built from the
        # GATE set, so a baselined or superseded finding is never annotated onto a PR as new.
        # Stdout normally; stderr only when stdout IS the SARIF document (`--format sarif` with
        # no `--out`), so a consumer piping that document never receives a non-JSON tail.
        lines = to_github_annotations(gated, top=n_annotate, uri_prefix=uri_prefix)
        if lines:
            sarif_on_stdout = args.format == "sarif" and not args.out
            print("\n".join(lines), file=sys.stderr if sarif_on_stdout else sys.stdout)
    _print_ci_summary(result.findings, args.fail_on, triggered, args.no_fail,
                      n_baselined=len(result.findings) - len(gated) - n_superseded,
                      n_superseded=n_superseded,
                      n_budget_exceeded=len(result.guards_budget_exceeded))
    return 1 if (triggered and not args.no_fail) else 0


def _print_ci_summary(findings: list[Finding], fail_on: str, triggered: bool, no_fail: bool,
                      n_baselined: int = 0, n_budget_exceeded: int = 0,
                      n_superseded: int = 0) -> None:
    """A single-line verdict on stderr for CI logs (survives `--out` redirection).

    The verdict reflects whether findings meet the gate — honest even under
    `--no-fail`, which is annotated rather than flipping FAIL to PASS. `n_baselined` is how
    many findings a `--baseline-snapshot` excluded from the gate (still shown, just non-gating).
    `n_budget_exceeded` (#677) is how many guards were killed over their time budget — named
    here because it can FAIL a run whose finding tally alone reads as a pass. `n_superseded`
    (#800) is how many findings are superseded history — visible in the report, non-gating, and
    kept OUT of the severity tally here (like the markdown header's `0 live; …` split), so
    `1 high … PASS` can never describe a superseded finding (#829 review)."""
    counts: dict[str, int] = {}
    for f in findings:
        if is_historical(f):
            continue
        counts[f.severity] = counts.get(f.severity, 0) + 1
    tally = ", ".join(
        f"{counts[s]} {s}" for s in ("critical", "high", "medium", "low", "info") if counts.get(s)
    ) or ("0 live" if n_superseded else "0 findings")
    base_note = f", {n_baselined} baselined (non-gating)" if n_baselined else ""
    if n_superseded:
        base_note += f", {n_superseded} superseded (non-gating)"
    if n_budget_exceeded:
        base_note += f", {n_budget_exceeded} guard(s) killed over time budget (scan PARTIAL)"
    verdict = "PASS"
    if triggered:
        verdict = "FAIL [--no-fail: exit 0]" if no_fail else "FAIL"
    print(f"agentsec: {tally}{base_note} — {verdict} (gate ≥{fail_on})", file=sys.stderr)


def _resolve_network(args: argparse.Namespace, repo: Path) -> tuple[int, bool, bool]:
    """The active egress tier + whether KEV/EPSS are on. `--kev`/`--epss` each imply tier 1
    unless a lower tier is forced (DO_NOT_TRACK / explicit --network tier0)."""
    from agentsec import net
    from agentsec.config import load_repo_config

    kev_on = bool(getattr(args, "kev", False))
    epss_on = bool(getattr(args, "epss", False))
    cli = getattr(args, "network", None)
    if (kev_on or epss_on) and cli is None:
        cli = "tier1"
    tier = net.resolve_tier(config_tier=load_repo_config(repo).network_tier, cli=cli)
    return tier, kev_on, epss_on


def _disclose_network(tier: int, kev_on: bool, epss_on: bool = False) -> None:
    """Print the egress disclosure (the manifest) when a run touches the network — or a clear
    note when `--kev`/`--epss` were requested but the active tier is 0 (e.g. DO_NOT_TRACK).

    `tier` must be the EFFECTIVE tier the audit actually ran at, not the resolved-from-flags one.
    `--deterministic` caps the tier to 0 inside `audit()` (`profile.network_tier`), so passing the
    raw tier here made the manifest announce an egress that never happened while nothing told the
    user the enrichment had been skipped — see `_cmd_audit`'s call site."""
    from agentsec import net

    if (kev_on or epss_on) and tier < 1:
        skipped = " + ".join(f for f, on in (("KEV", kev_on), ("EPSS", epss_on)) if on)
        print(f"note: --kev/--epss need network tier 1, but the active tier is 0 "
              f"(DO_NOT_TRACK / --deterministic?) — {skipped} enrichment skipped.", file=sys.stderr)
        return
    if tier < 1:
        return
    manifest = net.Manifest(tier=tier)
    if kev_on:
        manifest.record(net.EgressOp("--kev", "www.cisa.gov", "nothing (public CISA KEV catalog)", 1))
    if epss_on:
        manifest.record(net.EgressOp(
            "--epss", "api.first.org",
            "the CVE ids this audit found in your repo (your vulnerability profile; no code, no paths)", 1,
        ))
    print(manifest.render(), file=sys.stderr)


# The known egress surface, for `agentsec network` disclosure (RFC: the manifest).
_EGRESS_CATALOG: tuple[tuple[str, str, str, int], ...] = (
    ("semgrep (registry)", "semgrep.dev registry",
     "nothing about your code (downloads OSS rule packs; the local LLM pack runs at tier 0)", 1),
    ("pip-audit", "OSV / PyPI", "your Python package names+versions", 1),
    ("node-audit", "npm registry", "your dependency tree", 1),
    ("trivy (DB)", "trivy DB mirror", "nothing (downloads the vuln DB)", 1),
    ("--kev", "www.cisa.gov", "nothing (public CISA KEV catalog)", 1),
    ("--epss", "api.first.org",
     "the CVE ids this audit found in your repo (your vulnerability profile; no code, no paths)", 1),
    ("--check-updates", "raw.githubusercontent.com",
     "nothing about your repo (an unauthenticated GET of agentsec's versions.json)", 1),
    ("deps-monitor", "OSV / PyPI / npm / GitHub", "agentsec's own pinned dependency names", 1),
    ("react-doctor", "npm (npx tool fetch)",
     "nothing (Score API + Socket supply-chain disabled; npx fetches the tool)", 1),
    ("scorecard", "GitHub API + deps.dev + OSV",
     "the repo identifier (owner/repo) + your GITHUB_AUTH_TOKEN; reads repo metadata, no source code", 1),
    ("go-osv-hygiene", "OSV.dev / Go module proxy (proxy.golang.org)",
     "your go.mod-declared Go module names+versions", 1),
)


def _cmd_network(args: argparse.Namespace) -> int:
    """Show the resolved egress tier + the disclosure manifest (what leaves, at which tier)."""
    from agentsec import net

    tier, _, _ = _resolve_network(args, Path(args.path))
    print(f"agentsec network policy: TIER {tier}  (default is tier 0 / offline)")
    active = [op for op in _EGRESS_CATALOG if op[3] <= tier]
    blocked = [op for op in _EGRESS_CATALOG if op[3] > tier]
    if active:
        m = net.Manifest(tier=tier)
        for feat, dest, sends, t in active:
            m.record(net.EgressOp(feat, dest, sends, t))
        print("\nWould egress at this tier:")
        print(m.render())
    else:
        print("\nNothing leaves your machine at this tier.")
    if blocked:
        print("\nBlocked at this tier (raise the tier to enable):")
        for feat, dest, _sends, t in blocked:
            print(f"  {feat}  → {dest}  [needs tier {t}]")
    print("\nSet via `--network tierN`, AGENTSEC_NETWORK=tierN, or "
          ".agentsec/config.json {\"network\": {\"tier\": N}}. DO_NOT_TRACK=1 forces tier 0.")
    return 0


def _cmd_audit(args: argparse.Namespace) -> int:
    extra = _ingest_findings(args.ingest)
    baseline = Path(args.baseline) if args.baseline else None
    repo = Path(args.path)

    # --changed-files-only: resolve the changed file set from git before running
    changed_paths: frozenset[str] | None = None
    if getattr(args, "changed_files_only", None) is not None:
        ref = args.changed_files_only or "HEAD"
        changed_paths = _changed_files_from_git(repo, ref)
        if changed_paths is None:
            print(
                f"warning: --changed-files-only: git diff failed against '{ref}' "
                "— falling back to a full scan.",
                file=sys.stderr,
            )
        elif not changed_paths:
            print(
                f"--changed-files-only ({ref}): no changed files detected — no findings to report.",
                file=sys.stderr,
            )

    # --write-baseline always uses deterministic mode so the snapshot matches a gate that
    # excludes live-advisory scanners (a baseline can only be honest against reproducible
    # findings; mixing in node-audit/pip-audit/trivy drift would never re-match).
    deterministic = getattr(args, "deterministic", False)

    # --write-baseline: capture all current findings (no suppression) and save.
    if args.write_baseline:
        from agentsec.exceptions import write_baseline

        raw = run_audit(repo, run_scanners=not args.guards_only,
                        exceptions_path=Path(os.devnull), extra_findings=extra,
                        excludes=args.exclude, changed_paths=changed_paths,
                        deterministic=True, guard_budget=args.guard_budget,
                        guard_workers=_guard_workers(args))
        # #677 / #821 review High-1: a baseline is a claim about the WHOLE current posture,
        # so a partial scan must never bake one. Refuse (nothing written) rather than write
        # a snapshot that silently omits whatever the killed guard would have found — a
        # partial baseline with a success message is the quietest failure a gate can have.
        if raw.guards_budget_exceeded:
            print(
                "write-baseline refused: guard(s) killed over their time budget, so the scan "
                f"is partial: {', '.join(raw.guards_budget_exceeded)}. Nothing was written — "
                "re-run when the guards complete (or raise --guard-budget).",
                file=sys.stderr,
            )
            return 1
        n = write_baseline(raw.findings, Path(args.write_baseline), date.today())
        print(f"Wrote baseline with {n} accepted exception(s) → {args.write_baseline}")
        return 0

    tier, kev_on, epss_on = _resolve_network(args, repo)
    result = run_audit(repo, run_scanners=not args.guards_only,
                       exceptions_path=baseline, extra_findings=extra,
                       excludes=args.exclude, changed_paths=changed_paths,
                       kev=kev_on, epss=epss_on, network_tier=tier, deterministic=deterministic,
                       guard_budget=args.guard_budget, guard_workers=_guard_workers(args))
    if deterministic:
        print("deterministic mode: live-advisory scanners (node-audit, pip-audit, trivy, "
              "react-doctor) excluded for reproducibility; semgrep runs its local LLM/agent "
              "pack only (OSS registry packs dropped by the tier-0 cap).", file=sys.stderr)
    # Disclose the EFFECTIVE tier the audit ran at, not the flag-resolved one. `audit()` caps
    # `profile.network_tier` to 0 under `--deterministic`, which is what actually gates the
    # KEV/EPSS fetch — so reading it back is the single source of truth and cannot drift from
    # the gate the way a second `0 if deterministic else tier` here would.
    _disclose_network(result.profile.network_tier, kev_on, epss_on)
    if result.profile.uncovered_stacks:
        from agentsec.gap_report import record_gaps
        record_gaps(result.profile.uncovered_stacks)

    extra_meta = [_registry_stamp()]

    gate_exclude: frozenset[str] = frozenset()
    bsnap = getattr(args, "baseline_snapshot", None)
    if bsnap:
        from agentsec.drift import legacy_schema_rows, load_snapshot
        rows = load_snapshot(Path(bsnap))
        gate_exclude, n_reactivated = _baseline_gate_exclude(rows, result.findings)
        if n_reactivated:
            # The CI line will count these as findings the baseline "should" have covered; say why
            # before a user re-saves the baseline and bakes a live finding in (#853).
            print(f"agentsec: {n_reactivated} finding(s) the baseline recorded as superseded history "
                  "are live again and no longer exempt from the gate (was the schema dump removed, "
                  "renamed or moved?)", file=sys.stderr)
        n_legacy = legacy_schema_rows(rows)
        if n_legacy:
            # Old rows stay exempt (no verdict to compare), so the flip above cannot fire for them.
            # Say so rather than pass as a full check (#1038 round 1). A row cannot say whether a dump
            # ever answered it, and "no dump now" is the very state the flip leaves behind, so the
            # note cannot be skipped for a dump-less repo; the advice has to work there too (round 2).
            print(f"agentsec: the baseline predates the superseded verdict for {n_legacy} SQL "
                  "finding(s), so it cannot tell when one comes back live; re-save it (with the "
                  "schema dump in place, if the repo ships one)", file=sys.stderr)
    rc = _emit(result, args, extra_meta, gate_exclude=gate_exclude)

    if getattr(args, "suggest_excludes", False):
        from agentsec.advisor import suggest
        cands: list[object] = list(suggest(repo, result.profile, result.findings))
        print()
        print(_render_candidates(cands), end="")
        if cands:
            print("\nAdd to .agentsec/config.json to apply (or run `agentsec suggest-excludes --write`):\n")
            print(_config_snippet(cands))

    if getattr(args, "save_snapshot", None):
        from agentsec.drift import save_snapshot as _save_snapshot
        n = _save_snapshot(result.findings, Path(args.save_snapshot))
        print(f"Snapshot saved: {n} finding(s) → {args.save_snapshot}", file=sys.stderr)

    return rc


def _baseline_gate_exclude(
    rows: list[dict[str, Any]], findings: list[Finding]
) -> tuple[frozenset[str], int]:
    """The `--baseline-snapshot` ratchet set, plus how many current findings it no longer covers
    because they came back live.

    Only rows recorded as live are exempt. A row saved with `"historical": true` was superseded
    history when the baseline was accepted (the dump answered it), so it exempts nothing: while it
    stays historical `is_historical` keeps it non-gating anyway, and once the dump stops answering
    it (deleted, renamed, moved out of the scan) it gates like `audit` without a baseline does.
    Exempting every saved fingerprint let a HIGH come back live under a green ratchet (#853). A row
    without the key (saved before #853) stays exempt: the old behaviour, until it is re-saved.
    `rows` are `drift.load_snapshot` rows; a fingerprint with any non-`true` row is exempt, which
    is how `drift.diff_snapshot` reads duplicate rows too."""
    rows = [r for r in rows if r.get("fingerprint")]
    exempt = frozenset(r["fingerprint"] for r in rows if r.get("historical") is not True)
    was_history = {r["fingerprint"] for r in rows if r.get("historical") is True} - exempt
    n_reactivated = sum(
        1 for f in findings if not is_historical(f) and f.fingerprint() in was_history
    )
    return exempt, n_reactivated


def _cmd_triage(args: argparse.Namespace) -> int:
    from agentsec.triage_cli import run as _triage_run
    return _triage_run(args)


def _cmd_report(args: argparse.Namespace) -> int:
    from agentsec.audit import audit as run_audit_for_report
    from agentsec.drift import load_snapshot
    from agentsec.report import build_report
    from agentsec.triage import apply_triage, load_triage

    repo = Path(args.path)
    triage_path = Path(args.triage_file) if args.triage_file else repo / "agentsec-triage.json"

    if getattr(args, "from_snapshot", None):
        from agentsec.detect import detect
        # A selection flag that looks accepted but does nothing is Rule 3; say so once.
        if any(getattr(args, k, None) for k in ("guards_only", "deterministic", "network", "ingest")):
            print("note: --from-snapshot uses the snapshot's finding set; "
                  "--guards-only/--deterministic/--network/--ingest are ignored.", file=sys.stderr)
        profile = detect(repo)  # no audit ran in this branch, so detect the stack directly
        raw_dicts = load_snapshot(Path(args.from_snapshot))
        from agentsec.findings import Finding as F
        findings = [
            F(
                check_id=d.get("check_id", ""),
                severity=d.get("severity", "info"),
                title=d.get("title", ""),
                location=d.get("location", ""),
                message=d.get("message", ""),
                remediation=d.get("remediation", ""),
                url=d.get("url", ""),
                rule=d.get("rule", ""),
                standards=d.get("standards", []),
            )
            for d in raw_dicts
        ]
    else:
        # #864: the mirrored gate. This was `run_scanners=False`, so a scanner verdict `triage`
        # wrote could never appear in the per-check table. Same converters as `_cmd_audit`,
        # same default (scanners on); `--guards-only` is the pre-#864 guard-only set.
        from agentsec.triage_cli import source_lines
        scanners_ran = not getattr(args, "guards_only", False)
        tier, _kev, _epss = _resolve_network(args, repo)
        result = run_audit_for_report(
            repo,
            run_scanners=scanners_ran,
            extra_findings=_ingest_findings(getattr(args, "ingest", None)),
            network_tier=tier,
            deterministic=bool(getattr(args, "deterministic", False)),
        )
        findings = result.findings
        profile = result.profile  # reuse the audit's detection — no second repo walk
        # stderr: stdout is the report itself. The origin mix + skipped-scanner disclosure
        # travels with the report run the same way it does with triage (Rule 3).
        for line in source_lines(result, scanners_ran=scanners_ran):
            print(line, file=sys.stderr)

    verdicts = load_triage(triage_path)
    annotated = apply_triage(findings, verdicts)

    baseline_findings = None
    if getattr(args, "compare", None):
        baseline_dicts = load_snapshot(Path(args.compare))
        from agentsec.findings import Finding as F
        baseline_findings = [
            F(
                check_id=d.get("check_id", ""),
                severity=d.get("severity", "info"),
                title=d.get("title", ""),
                location=d.get("location", ""),
                message=d.get("message", ""),
                # Reconstruct `rule` too (mirrors the --from-snapshot block): a baseline
                # finding's recomputed fingerprint must match the saved one, which keys on
                # rule_or_check_id — so omitting `rule` diverges for sub-ruled guards / semgrep
                # findings where rule != check_id.
                rule=d.get("rule", ""),
            )
            for d in baseline_dicts
        ]

    from agentsec.checklist import load_checklist

    cl = load_checklist()
    manual_items = [
        it for it in cl.items
        if it.status == "manual" and it.applicable(profile.features)
    ]

    from datetime import date
    run_date = date.today().isoformat()
    report = build_report(annotated, baseline_findings, run_date, manual_items=manual_items)
    md = report.to_markdown()

    if getattr(args, "section", None):
        section = args.section
        parts = md.split("\n## ")
        for part in parts:
            if part.lower().startswith(section.lower()):
                print("## " + part if not part.startswith("#") else part)
                return 0
        print(f"Section '{section}' not found.", file=sys.stderr)
        return 1

    out_path = getattr(args, "out", None)
    if out_path:
        Path(out_path).write_text(md, encoding="utf-8")
        print(f"Report written to {out_path}")
    else:
        print(md)
    return 0


def _registry_stamp(*, markdown: bool = True) -> str:
    """Checklist-registry version + sha + offline staleness meta line (two-clock
    reproducibility stamp; RFC #253 Phase 1 — age is informational text only, never
    network, never affects findings or the exit code).

    Past `update_check.STALE_THRESHOLD_DAYS` (90 days, the RFC's own Phase 1 design —
    see docs/knowledge/rfc-version-staleness-update-awareness.md) appends one soft
    advisory line nudging `doctor --check-updates`. Still zero network here: the line
    is a pure function of `age_days`, the same offline `released`-date arithmetic as
    the rest of this stamp.

    `markdown=False` drops the `_..._` label emphasis for plain-text callers (doctor) —
    cleaner than stripping underscores after the fact (a literal underscore elsewhere in
    the line, e.g. a version suffix, would otherwise be mangled)."""
    from agentsec.checklist import checklist_sha, load_checklist
    from agentsec.update_check import stale_advisory_line

    cl = load_checklist()
    age = cl.age_days(date.today())
    plural = "day" if age == 1 else "days"
    label = "_Checklist registry:_" if markdown else "Checklist registry:"
    line = (
        f"{label} v{cl.version} (sha256 {checklist_sha()[:12]}), "
        f"released {cl.released}, {age} {plural} old"
    )
    advisory = stale_advisory_line(age)
    if advisory is None:
        return line
    return f"{line}\n{advisory}"


def _detect_text(prof: StackProfile) -> str:
    """The `agentsec detect` output as a string (reused by `scan`'s detect.txt)."""
    lines = [
        f"Stack profile for {prof.root}:",
        f"  {prof.summary()}",
        f"  features: {sorted(prof.features)}",
    ]
    if prof.python_dirs:
        lines.append(f"  python dirs: {prof.python_dirs}")
    if prof.frontend_dir:
        lines.append(f"  frontend dir: {prof.frontend_dir}")
    if prof.sql_dir:
        lines.append(f"  sql dir: {prof.sql_dir}")
    for stack in sorted(prof.uncovered_stacks):
        lines.append(
            f"  no dedicated guard suite yet: {stack} — run `agentsec report-gap {stack}` to flag this"
        )
    for lang in sorted(prof.foreign_languages):
        lines.append(
            f"  unscanned language: {lang} — agentsec does not audit {lang}, "
            f"findings above do not cover it"
        )
    for artifact in sorted(prof.foreign_artifacts):
        lines.append(
            f"  artifact-layer language evidence: {artifact} — found in a Docker base image, not "
            f"repo source; agentsec's source-only detection cannot see this language at all"
        )
    return "\n".join(lines) + "\n"


def _cmd_scan(args: argparse.Namespace) -> int:
    """One-shot: detect + a single audit → write detect.txt + audit.md + audit.sarif
    (+ a starter exceptions registry when none exists) into an output dir. The
    'just run it' entrypoint. Honors `--fail-on`/`--no-fail` so it is CI-usable too."""
    from agentsec.detect import detect

    repo = Path(args.path)
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    # `setup` is opt-in and explicit (never auto-download): only run when asked.
    if args.setup:
        from agentsec.setup import setup

        print("scan: installing the applicable scanner toolchain first (--setup)…", file=sys.stderr)
        print(setup(repo, dry_run=False).render(), file=sys.stderr)

    prof = detect(repo)
    (out_dir / "detect.txt").write_text(_detect_text(prof), encoding="utf-8")

    extra = _ingest_findings(args.ingest)
    baseline = Path(args.baseline) if args.baseline else None
    # `scan` has no --guard-budget flag (the 'just run it' entrypoint stays flag-light);
    # it gets the default budget unconditionally — hostile-input protection on by default.
    result = run_audit(repo, run_scanners=not args.guards_only,
                       exceptions_path=baseline, extra_findings=extra,
                       guard_budget=DEFAULT_GUARD_BUDGET, guard_workers=default_guard_workers())

    meta = _meta_lines(result, [_registry_stamp()])
    (out_dir / "audit.md").write_text(_render_markdown(result, meta), encoding="utf-8")
    (out_dir / "audit.sarif").write_text(
        # Same disclosure as audit.md's footer — the two artifacts must not disagree (#434).
        to_sarif_json(result.findings, notifications=result.coverage_notices(),
                      budget_exceeded=result.guards_budget_exceeded),
        encoding="utf-8",
    )

    # Scaffold a starter exceptions registry ONLY when none exists (never clobber an
    # existing one — neither the repo's nor a previous scan's).
    from agentsec.exceptions import DEFAULT_REGISTRY

    scaffolded = False
    out_exc = out_dir / DEFAULT_REGISTRY
    if not (repo / DEFAULT_REGISTRY).exists() and not out_exc.exists():
        out_exc.write_text(json.dumps({"exceptions": []}, indent=2) + "\n", encoding="utf-8")
        scaffolded = True

    artifacts = ["detect.txt", "audit.md", "audit.sarif"]
    if scaffolded:
        artifacts.append(f"{DEFAULT_REGISTRY} (starter)")
    print(f"agentsec scan → {out_dir}/")
    print(f"  wrote: {', '.join(artifacts)}")
    print("\n".join(meta))
    return _gate(result, args.fail_on, args.no_fail)


def _cmd_coverage(args: argparse.Namespace) -> int:
    """Checklist coverage score card: covered / partial / manual / n-a per section."""
    from agentsec.coverage import coverage, to_dashboard, to_json, to_markdown, write_tracker

    result = coverage(Path(args.path))
    if args.format == "json":
        out = to_json(result)
    elif args.format == "dashboard":
        out = to_dashboard(result)
    else:
        out = to_markdown(result)
    if args.out:
        Path(args.out).write_text(out, encoding="utf-8")
        print(f"Wrote coverage report → {args.out}")
    else:
        print(out, end="")

    if args.write_tracker:
        tracker = Path(__file__).resolve().parents[1] / "docs" / "knowledge" / "checklist-gaps.md"
        if write_tracker(tracker):
            print(f"Updated generated coverage table → {tracker}", file=sys.stderr)
        else:
            print(
                f"--write-tracker: {tracker} missing or has no generated-block markers "
                "(this flag is for the agentsec repo itself)",
                file=sys.stderr,
            )
    return 0  # informational; the CI gate stays `audit`'s job


def _cmd_ai_bom(args: argparse.Namespace) -> int:
    """AI Bill of Materials: static inventory of the repo's AI supply chain."""
    from agentsec.ai_bom import ai_bom, to_cyclonedx, to_json, to_markdown

    bom = ai_bom(Path(args.path))
    if args.format == "cyclonedx":
        out = to_cyclonedx(bom)
    elif args.format == "markdown":
        out = to_markdown(bom)
    else:
        out = to_json(bom)
    if args.out:
        Path(args.out).write_text(out, encoding="utf-8")
        print(f"Wrote AI-BOM ({bom.component_count} components) → {args.out}")
    else:
        print(out, end="")
    return 0  # informational; not a CI gate


def _resolve_db_schemas(flag: str | None, repo: Path) -> str:
    """The PostgREST-exposed schema list to lint with Splinter.

    Precedence: `--db-schemas` flag → `PGRST_DB_SCHEMAS` env → auto-derive from the
    repo's migration SQL (`detect_exposed_schemas`) → `public`. Auto-derivation reuses
    the same signal the static `public-table-rls` guard uses (schemas GRANTed to anon/
    authenticated, or named in a literal `pgrst.db_schemas`), so a live run covers the
    same exposed schemas the static audit does."""
    if flag:
        return flag
    env = os.getenv("PGRST_DB_SCHEMAS")
    if env:
        return env
    try:
        from agentsec.detect import detect
        from agentsec.guards.base import iter_files, read, strip_sql_comments
        from agentsec.guards.public_table_rls import detect_exposed_schemas

        prof = detect(repo)
        sql_dir = repo / prof.sql_dir if prof.sql_dir else repo
        texts = [strip_sql_comments(read(f)) for f in iter_files(sql_dir, (".sql",))]
        schemas = detect_exposed_schemas(texts) if texts else {"public"}
        return ",".join(sorted(schemas))
    except Exception:
        return "public"


def _consent_remote(
    url: str, allow_flag: bool, *, flag_name: str, label: str, intrusive: bool
) -> bool:
    """Decide whether a live scan against `url` may proceed, given its locality.

    Local targets always proceed. A **remote** target needs explicit consent:
    - `intrusive` scans (active ZAP / Schemathesis fuzzing) are **hard-refused**
      unless `allow_flag` is set — never auto-approved by a prompt, since they send
      real attack/mutating traffic.
    - read-only scans (Splinter DB lint) additionally accept an interactive yes on a
      TTY; non-interactively they require `allow_flag`.

    This is the Human-Loop "action question" (plain language, never a security
    judgment); the loud notice goes to stderr so it survives `--out` redirection."""
    from agentsec.targets import classify_host, describe, extract_host

    if classify_host(url) == "local":
        return True
    desc = describe(url)  # e.g. "remote (db.x.supabase.co, hosted Supabase project)"
    if allow_flag:
        print(f"⚠️  {label}: {desc} — proceeding ({flag_name} set).", file=sys.stderr)
        return True
    if intrusive:
        print(
            f"⛔ Refusing intrusive scan: {label} is {desc}. It sends real attack/mutating "
            f"traffic — re-run with {flag_name}, and only against a non-production system "
            "you own.",
            file=sys.stderr,
        )
        return False
    if sys.stdin.isatty():
        try:
            answer = input(f"⚠️  Scan this remote {label} ({extract_host(url)})? [y/N] ").strip().lower()
        except EOFError:
            answer = ""
        if answer in ("y", "yes"):
            return True
        print(f"Skipping {label}: not confirmed.", file=sys.stderr)
        return False
    print(
        f"⚠️  {label}: {desc} — refused. Pass {flag_name} to scan it non-interactively.",
        file=sys.stderr,
    )
    return False


def _resolve_api_token(args: argparse.Namespace) -> str:
    """Resolve the bearer token for the authenticated live scanners (auth bootstrap).

    Precedence: an explicit `--api-token`, else `--auth-cmd` stdout, else a
    `--supabase-login` password grant (params from flags, falling back to env). Returns
    `""` (unauthenticated) when none apply. Prints a concise stderr note and **never
    echoes the token or password**."""
    if args.api_token:
        return str(args.api_token)
    if getattr(args, "auth_cmd", None):
        from agentsec.live import mint_token_cmd

        tok = mint_token_cmd(args.auth_cmd)
        print(f"auth: --auth-cmd {'minted a token' if tok else 'produced no token'}.", file=sys.stderr)
        return tok
    if getattr(args, "supabase_login", False):
        from agentsec.live import mint_supabase_token

        tok = mint_supabase_token(
            args.supabase_url or os.getenv("SUPABASE_URL") or "",
            args.supabase_anon_key or os.getenv("SUPABASE_ANON_KEY") or "",
            args.supabase_email or os.getenv("TEST_USER_EMAIL") or "",
            args.supabase_password or os.getenv("TEST_USER_PASSWORD") or "",
        )
        ok = "minted a token" if tok else "failed (check --supabase-url / anon-key / credentials)"
        print(f"auth: --supabase-login {ok}.", file=sys.stderr)
        return tok
    return ""


def _cmd_live(args: argparse.Namespace) -> int:
    """Static audit + live scanners (ZAP / Splinter / Schemathesis / jwt_tool), one report."""
    from agentsec.live import (
        _load_schemathesis_skips,
        run_garak,
        run_jwt_tool,
        run_promptfoo,
        run_schemathesis,
        run_splinter,
        run_zap,
    )

    token = _resolve_api_token(args)

    if not any([args.target_url, args.db_url, args.schemathesis_url, args.jwt_url,
                args.garak_target, args.promptfoo_config]):
        print(
            "agentsec live: nothing live to run — pass --target-url (ZAP DAST), "
            "--db-url (Splinter), --schemathesis-url (API fuzz), --jwt-url (JWT scan), "
            "--garak-target / --promptfoo-config (LLM red-team).",
            file=sys.stderr,
        )

    extra = _ingest_findings(args.ingest)
    live_meta: list[str] = [_registry_stamp()]
    if args.target_url:
        # The active API scan (and its OpenAPI-spec import) is intrusive; gate it on
        # locality. Passive baseline is left runnable anywhere.
        allow_target = True
        if args.zap_active:
            allow_target = _consent_remote(
                args.target_url, args.allow_remote_target,
                flag_name="--allow-remote-target", label="ZAP active-scan target", intrusive=True,
            )
        z = run_zap(args.target_url, image=args.zap_image, active=args.zap_active,
                    openapi_url=args.zap_openapi or args.target_url, auth_header=token,
                    network_host=args.zap_network_host, allow_remote=allow_target,
                    rules_tsv=args.zap_rules or "")
        extra += z.findings
        mode = "active API scan" if args.zap_active else "baseline"
        live_meta.append(
            f"_ZAP DAST ({mode}, {args.target_url}):_ "
            + (f"ran — {len(z.findings)} alert(s)" if z.ran else f"skipped ({z.skip_reason})")
        )
    if args.db_url:
        allow_db = _consent_remote(
            args.db_url, args.allow_remote_db,
            flag_name="--allow-remote-db", label="database", intrusive=False,
        )
        db_schemas = _resolve_db_schemas(args.db_schemas, Path(args.path))
        s = run_splinter(args.db_url, splinter_sql=args.splinter_sql,
                         allow_fetch=not args.no_splinter_fetch, db_schemas=db_schemas,
                         allow_remote=allow_db)
        extra += s.findings
        live_meta.append(
            f"_Splinter DB lint (schemas: {db_schemas}):_ "
            + (f"ran — {len(s.findings)} lint(s)" if s.ran else f"skipped ({s.skip_reason})")
        )
    if args.schemathesis_url:
        allow_st = _consent_remote(
            args.schemathesis_url, args.allow_remote_target,
            flag_name="--allow-remote-target", label="Schemathesis fuzz target", intrusive=True,
        )
        sk = run_schemathesis(
            args.schemathesis_url, token=token, origin=args.origin or "",
            max_examples=args.max_examples,
            skip_paths=_load_schemathesis_skips(args.schemathesis_skip),
            allow_remote=allow_st,
        )
        extra += sk.findings
        live_meta.append(
            f"_Schemathesis ({args.schemathesis_url}):_ "
            + (f"ran — {len(sk.findings)} finding(s)" if sk.ran else f"skipped ({sk.skip_reason})")
        )
    if args.jwt_url:
        jt = run_jwt_tool(args.jwt_url, token=token, canary=args.jwt_canary or "")
        extra += jt.findings
        live_meta.append(
            f"_jwt_tool ({args.jwt_url}):_ "
            + (f"ran — {len(jt.findings)} finding(s)" if jt.ran else f"skipped ({jt.skip_reason})")
        )
    if args.garak_target:
        garak_kwargs = {}
        if args.garak_probes:
            garak_kwargs["probes"] = args.garak_probes
        if args.garak_generations is not None:
            garak_kwargs["generations"] = args.garak_generations
        g = run_garak(args.garak_target, **garak_kwargs)
        extra += g.findings
        live_meta.append(
            f"_garak ({args.garak_target}):_ "
            + (f"ran — {len(g.findings)} finding(s)" if g.ran else f"skipped ({g.skip_reason})")
        )
    if args.promptfoo_config:
        pf = run_promptfoo(args.promptfoo_config)
        extra += pf.findings
        live_meta.append(
            f"_promptfoo ({args.promptfoo_config}):_ "
            + (f"ran — {len(pf.findings)} finding(s)" if pf.ran else f"skipped ({pf.skip_reason})")
        )

    baseline = Path(args.baseline) if args.baseline else None
    result = run_audit(Path(args.path), run_scanners=not args.guards_only,
                       exceptions_path=baseline, extra_findings=extra,
                       skip_static=args.live_only, excludes=args.exclude,
                       guard_budget=args.guard_budget, guard_workers=_guard_workers(args))
    return _emit(result, args, live_meta)


def _cmd_scan_live_url(args: argparse.Namespace) -> int:
    """Outside-in probe of a deployed app's Supabase backend — no repo, no DB DSN.

    Two-invocation flow, by design: run once with no `--verify-token` to get a fresh token and
    placement instructions; run again with that token once it's placed, which is what actually
    performs the ownership check and, only on success, the probes. This is the ownership GATE,
    not a rate limit — no probe below ever runs without it, regardless of flags."""
    from agentsec.livescan import (
        WELL_KNOWN_PATH,
        discover_supabase_config,
        edge_functions_not_probed,
        generate_verify_token,
        probe_exposed_tables,
        probe_pg_graphql,
        probe_public_storage,
        verify_ownership_dns,
        verify_ownership_file,
    )

    if urlsplit(args.url).scheme != "https":
        print("scan-live-url: URL must be https:// (refusing to probe a plaintext target).", file=sys.stderr)
        return 2

    if not args.verify_token:
        token = generate_verify_token()
        origin = f"{urlsplit(args.url).scheme}://{urlsplit(args.url).netloc}"
        print(
            "scan-live-url requires proof you own this URL before probing it.\n\n"
            f"1. Create a file at {origin}{WELL_KNOWN_PATH} containing exactly:\n"
            f"   {token}\n"
            "   (or, if you control DNS instead: a TXT record at "
            f"_agentsec-verify.{urlsplit(args.url).hostname} with that same value)\n\n"
            f"2. Re-run: agentsec scan-live-url {args.url} --verify-token {token}"
            + (" --verify-method dns" if args.verify_method == "dns" else ""),
        )
        return 2

    method = args.verify_method or "file"
    verify = verify_ownership_dns if method == "dns" else verify_ownership_file
    ownership = verify(args.url, args.verify_token)
    if not ownership.verified:
        print(f"scan-live-url: ownership not verified ({ownership.method}): {ownership.reason}", file=sys.stderr)
        return 2
    print(f"Ownership verified via {ownership.method}.", file=sys.stderr)

    supabase_url = args.supabase_url or ""
    anon_key = args.supabase_anon_key or ""
    if not (supabase_url and anon_key):
        d_url, d_key = discover_supabase_config(args.url)
        supabase_url = supabase_url or d_url
        anon_key = anon_key or d_key
    if not (supabase_url and anon_key):
        print(
            "scan-live-url: no Supabase URL + anon key found in the page (pass --supabase-url "
            "and --supabase-anon-key explicitly, or this app may not use Supabase).",
            file=sys.stderr,
        )
        return 2

    findings: list[Finding] = []
    probes_ran = 0
    meta: list[str] = [f"_Target:_ {args.url}", f"_Supabase project:_ {supabase_url}"]
    for probe in (probe_exposed_tables, probe_public_storage, probe_pg_graphql):
        r = probe(supabase_url, anon_key)
        findings += r.findings
        if r.ran:
            probes_ran += 1
        meta.append(f"_{r.name}:_ " + (f"ran — {len(r.findings)} finding(s)" if r.ran else f"skipped ({r.skip_reason})"))
    edge = edge_functions_not_probed()
    meta.append(f"_{edge.name}:_ not probed ({edge.skip_reason})")

    if args.format == "sarif":
        out = to_sarif_json(findings, notifications=[m.strip("_") for m in meta])
    elif args.format == "summary":
        out = to_human_summary(findings) + "\n---\n\n## Technical detail (file, line, rule)\n\n" + to_markdown(findings)
    else:
        out = to_markdown(findings)
    if args.out:
        Path(args.out).write_text(out, encoding="utf-8")
        print(f"Wrote {args.format} report → {args.out}")
    else:
        print(out)
    print("\n".join(meta), file=sys.stderr)

    if probes_ran == 0:
        # "A failure that presents as success" (review-doctrine rule 3, #904 L1): every probe
        # was SKIPPED (wrong anon key, paused project, unreachable endpoints), so findings=[]
        # not because the target is clean but because nothing was actually checked. An empty
        # PASS/exit-0 here would let a CI gate green-light a scan that never ran. Signal it as
        # INCOMPLETE with exit 2 — the same "could not produce a result" family as the ownership
        # / no-config refusals above, and therefore NOT suppressible by --no-fail (which only
        # governs findings-based gating).
        print(
            "agentsec scan-live-url: INCOMPLETE — 0 of 3 probes ran (see per-probe skip "
            "reasons above); the target was not actually checked.",
            file=sys.stderr,
        )
        return 2

    fail_rank = SEVERITY_RANK[args.fail_on]
    triggered = any(SEVERITY_RANK[f.severity] <= fail_rank for f in findings)
    verdict = "FAIL" if triggered else "PASS"
    print(f"agentsec scan-live-url: {len(findings)} finding(s) — {verdict}", file=sys.stderr)
    return 1 if (triggered and not args.no_fail) else 0


def _cmd_harden_host(args: argparse.Namespace) -> int:
    """Audit the LIVE host's hardening (read-only): SSH, UFW, fail2ban, auto-updates, listeners.

    A deliberately separate verb from `audit` — it reads the running host (sshd -T, ufw status,
    systemctl, ss), departing from agentsec's repo-static, zero-host-read posture. Every probe is
    read-only and never raises; a probe that can't read (no binary / needs root) is disclosed, not
    failed. Findings render through the same markdown/SARIF emitters and obey `--fail-on`."""
    from agentsec.hostaudit import audit_host

    result = audit_host()
    findings = result.findings

    if args.format == "sarif":
        out = to_sarif_json(findings)
    elif args.format == "summary":
        out = (
            to_human_summary(findings)
            + "\n---\n\n## Technical detail (rule, location)\n\n"
            + to_markdown(findings, top=getattr(args, "top", None))
        )
    else:
        out = to_markdown(findings, top=getattr(args, "top", None))

    # Probe disclosure: what was read vs. couldn't be read (and why) — honesty about coverage.
    # A probe can be `ok=True` AND still carry a `reason` (e.g. restart-required degrading to its
    # kernel-only fallback when needrestart is present but unusable) — print it here too, not only
    # on an outright skip, or the one-time disclosure never reaches the report.
    ran = [f"{p.name} ({p.reason})" if p.reason else p.name for p in result.probes if p.ok]
    skipped = [f"{p.name} ({p.reason})" for p in result.probes if not p.ok]
    meta = [
        "_agentsec harden-host — live host audit (read-only)_",
        f"_Probed:_ {', '.join(ran) or 'none'}",
        f"_Could not read:_ {', '.join(skipped) or 'none'}",
    ]
    # Only hint sudo when a probe actually skipped for a root/permission reason — not when the
    # binary is simply absent (sudo won't conjure a missing `ufw`/`ss`). Name the real probes.
    root_skipped = [p.name for p in result.probes if not p.ok and "root" in p.reason.lower()]
    if root_skipped:
        meta.append(f"_Run with sudo for the root-only probes ({', '.join(root_skipped)})._")

    if args.out:
        Path(args.out).write_text(out, encoding="utf-8")
        print(f"Wrote {args.format} report → {args.out}")
        if args.format != "sarif":
            print("\n".join(meta))
    else:
        print(out)
        if args.format != "sarif":
            print("\n" + "\n".join(meta))

    fail_rank = SEVERITY_RANK[args.fail_on]
    gated = _gating(findings)  # host findings are never SQL; shared so the gate sites cannot drift
    triggered = any(SEVERITY_RANK[f.severity] <= fail_rank for f in gated)
    _print_ci_summary(findings, args.fail_on, triggered, args.no_fail,
                      n_superseded=len(findings) - len(gated))
    return 1 if (triggered and not args.no_fail) else 0


def _add_enrichment_args(p: argparse.ArgumentParser) -> None:
    """`--kev`/`--epss`: `audit`-only, not `live`. Review #609 M1: `live` accepted both flags via
    the shared `_add_audit_args` but `_cmd_live` never threaded kev/epss/network_tier through to
    `run_audit` or called `_disclose_network` — a silent no-op, the exact "failure that presents
    as success" this codebase's own review doctrine (rule 3) names. Rejecting the flags on `live`
    (an argparse error) is safer than a flag that looks accepted but does nothing."""
    p.add_argument(
        "--kev", action="store_true",
        help="Enrich findings with the CISA Known-Exploited (KEV) catalog (a Tier-1 public fetch — "
             "sends nothing about your code; implies --network tier1). Known-exploited CVEs lead their severity.",
    )
    p.add_argument(
        "--epss", action="store_true",
        help="Enrich findings with FIRST.org EPSS exploit-probability scores (a Tier-1 public fetch — "
             "sends the CVE ids this audit found in your repo, your vulnerability profile, no code or "
             "paths; implies --network tier1). High-probability (>=10%%) CVEs lead their severity.",
    )


def _add_scanner_selection_args(p: argparse.ArgumentParser) -> None:
    """The four options that decide WHICH checks feed a run — shared by `audit`/`live` (via
    `_add_audit_args`) and, since #864, by `triage` and `report`. One helper so the three
    commands cannot disagree about the selection surface: triage classifies, and report
    reports on, the same set audit reported, with the same defaults (scanners ON)."""
    p.add_argument(
        "--guards-only", action="store_true",
        help="Skip the external scanners; run only the dependency-free static guards",
    )
    p.add_argument(
        "--deterministic", action="store_true",
        # The "implied by --write-baseline" clause lives on --write-baseline itself (audit-only):
        # this string is shared with triage/report, which have no such flag (#876 review L1).
        # The semgrep local-pack degradation clause (#863/#875) belongs here too: it describes
        # what --deterministic does to semgrep, which is not audit-specific, so all four commands
        # disclose it (test_audit_help_discloses_semgrep_degradation_under_deterministic).
        help="Reproducible mode for CI gates: run guards + static scanners but exclude "
             "live-advisory scanners (node-audit, pip-audit, trivy, react-doctor) whose "
             "results drift with an external DB. Also caps the network tier to 0, so semgrep "
             "runs its local LLM/agent pack only; its OSS registry packs (p/python, "
             "p/owasp-top-ten, p/secrets) are a network fetch and are dropped.",
    )
    p.add_argument(
        "--network", choices=["tier0", "tier1", "tier2"], metavar="tier0|tier1|tier2",
        help="Network-egress tier (default: tier0 / offline). tier1 = public advisory fetch "
             "(e.g. --kev/--epss); tier2 = scan-data egress. DO_NOT_TRACK=1 forces tier0. See `agentsec network`.",
    )
    p.add_argument(
        "--ingest", action="append", metavar="KIND=PATH",
        help="Merge an external report (zap=…, splinter=…, sarif=…). Repeatable.",
    )


def _add_audit_args(p: argparse.ArgumentParser) -> None:
    """Options shared by `audit` and `live`."""
    p.add_argument("path", nargs="?", default=".", help="Repo path (default: .)")
    p.add_argument("--format", choices=["markdown", "summary", "sarif"], default="markdown")
    p.add_argument("--out", help="Write the report to this file instead of stdout")
    p.add_argument(
        "--sarif-out", metavar="FILE",
        help="Also write a SARIF report to FILE (from the same run) — pair with a human "
             "--format/--out to get both a report and a code-scanning artifact in one pass",
    )
    p.add_argument(
        "--fail-on", choices=list(SEVERITY_RANK), default="high",
        help="Minimum severity that fails the run (default: high)",
    )
    p.add_argument("--no-fail", action="store_true", help="Always exit 0 (report only)")
    p.add_argument(
        "--top", type=int, metavar="N",
        help="Show only the N most-severe findings in the detail list (the full tally "
             "still appears in 'Summary by check'; the report states 'showing N of M')",
    )
    p.add_argument(
        "--annotations", type=_non_negative_int, metavar="N",
        help="Also print GitHub Actions workflow commands (::error/::warning/::notice) for the "
             "N most-severe findings of any severity, so they show inline on the PR. Baselined and "
             "superseded findings are never annotated; 0 prints none. Printed to stdout after "
             "the report (to stderr when stdout carries the SARIF document itself)",
    )
    _add_scanner_selection_args(p)
    p.add_argument(
        "--baseline", metavar="FILE",
        help="Exception registry to apply (default: ./agentsec-exceptions.json if present)",
    )
    p.add_argument(
        "--exclude", action="append", metavar="PATTERN",
        help="Drop findings whose path matches PATTERN (a dir, a path prefix, a glob, "
             "or a bare name matched as any path segment). Repeatable.",
    )
    p.add_argument(
        "--changed-files-only", metavar="REF", nargs="?", const="HEAD", dest="changed_files_only",
        help="Only report findings in files changed since REF (default: HEAD). "
             "Uses `git diff --name-only REF` — requires git. Falls back to a full scan on failure.",
    )
    p.add_argument(
        "--guard-budget", type=float, default=DEFAULT_GUARD_BUDGET, metavar="SECONDS",
        help="Per-guard wall-clock budget (default: %(default)s). Guards run in a killable "
             "child process; one stuck in an unbounded loop is killed, reported distinctly "
             "('killed over time budget'), and FAILS the gate — instead of hanging the job "
             "until an external kill that reports nothing. 0 disables (legacy in-process run).",
    )
    p.add_argument(
        "--guard-workers", type=_worker_count, default=None, metavar="N",
        help="Budgeted guard children to run in parallel (default: the usable cores, "
             "lowered to a Linux container's CPU quota, capped at 8). Findings and their "
             "order are the same at any N; 1 runs one child, as before. Ignored with "
             "--guard-budget 0.",
    )


def _non_negative_int(value: str) -> int:
    n = int(value)
    if n < 0:
        raise argparse.ArgumentTypeError(f"must be 0 or more, got {n}")
    return n


def _worker_count(value: str) -> int:
    n = int(value)
    if n < 1:
        raise argparse.ArgumentTypeError(f"must be at least 1, got {n}")
    return n


def _guard_workers(args: argparse.Namespace) -> int:
    """The `--guard-workers` value, or the auto count when the flag was not given."""
    n: int | None = getattr(args, "guard_workers", None)
    return n if n is not None else default_guard_workers()


def _cmd_corpus_scan(args: argparse.Namespace) -> int:
    import dataclasses

    from agentsec import net
    from agentsec.config import load_repo_config
    from agentsec.corpus import (
        corpus_scan,
        is_local_repo,
        is_url_like,
        local_entry_is_not_a_git_repo,
        report_to_json,
        report_to_markdown,
        report_to_terminal,
        unique_raw_scan_names,
    )

    today = date.today()

    # Assemble the explicit repo set: --repos plus any --repos-file (one repo path/URL per line,
    # `#` comments + blanks ignored — a gitignored local list of PRIVATE app repos we can scan
    # without committing their paths into the public SEED_REPOS). A `#` is a comment only as a
    # whole-line prefix or when preceded by whitespace (requirements-file convention), so a path
    # containing a literal `#` (e.g. `/data/repo#2`) is preserved, not truncated.
    repos: list[str] = list(args.repos or [])
    if getattr(args, "repos_file", None):
        try:
            # `utf-8-sig` strips a BOM if present. A file saved by Notepad (the likeliest
            # way a Windows user hands over a repo list) starts with U+FEFF, which lands on
            # the FIRST entry as an invisible character and makes it fail to resolve
            # (#477 review). A file without a BOM decodes identically.
            for line in Path(args.repos_file).read_text(encoding="utf-8-sig").splitlines():
                stripped = line.strip()
                if not stripped or stripped.startswith("#"):
                    continue
                entry = re.split(r"\s#", stripped, maxsplit=1)[0].rstrip()
                if entry:
                    repos.append(entry)
        except OSError as exc:
            print(f"error: could not read --repos-file {args.repos_file}: {exc}", file=sys.stderr)
            return 2
        except UnicodeDecodeError:
            # NOT covered by the OSError arm: `UnicodeDecodeError` is a ValueError, so an
            # un-decodable file crashed the CLI with a traceback instead of exiting cleanly
            # (#466 gate). The BOM comment above is exactly why this is reachable: Notepad's
            # "Unicode" save is UTF-16LE, not UTF-8, so the very editor that motivates
            # `utf-8-sig` is also the one that produces the file this arm catches.
            print(
                f"error: --repos-file {args.repos_file} is not UTF-8 text "
                "(save it as UTF-8; Notepad's 'Unicode' option writes UTF-16).",
                file=sys.stderr,
            )
            return 2
    no_seeds = getattr(args, "no_seeds", False)

    if no_seeds and not repos:
        print("error: --no-seeds needs at least one repo via --repos/--repos-file (nothing to scan).",
              file=sys.stderr)
        return 2

    # Catch a typo'd LOCAL path before it's misread as a remote repo: a PLAIN FILESYSTEM PATH (no
    # URL/UNC shape at all) that isn't an existing directory is a missing local path, not something
    # to clone over the network (otherwise it silently becomes a confusing tier-1/clone-failed
    # error). The test is `is_url_like`, never "not remote": an authority-bearing entry that
    # `is_local_repo` refuses (`file://198.51.100.7/share`, `\\host\share`, `FILE://…`) is a routing
    # decision for the tier gate below, and reporting it as a missing local path was both a hard
    # rc=2 where the contract is a graceful "needs network tier 1" and a false diagnosis (#477 M1).
    missing_local = [r for r in repos if not is_url_like(r) and not is_local_repo(r)]
    if missing_local:
        print(
            "error: local repo path(s) not found: " + ", ".join(missing_local) + "\n"
            "(an entry with no clone-URL scheme is treated as a local path — check for a typo, "
            "or use a full https://… / git@… URL for a remote repo).",
            file=sys.stderr,
        )
        return 2

    # The other half of the same preflight: the path exists but holds no git repository. Local repos
    # are reached via `git clone <path>` (that is what "scanned at its committed HEAD" means), so
    # this otherwise surfaces as an opaque `clone-failed` row the user can do nothing with (#477 L3).
    # A WARNING, not an `rc=2` like the typo gate beside it: recognising a repo from its on-disk
    # layout is a heuristic diagnosis, and a diagnosis must never be able to fail a run that git
    # would have completed. So it adds information and takes nothing away.
    not_git = [r for r in repos if local_entry_is_not_a_git_repo(r)]
    if not_git:
        print(
            "warning: not a git repository: " + ", ".join(not_git) + "\n"
            "(corpus-scan clones each local repo at its committed HEAD, so --repos wants a repo "
            "root — a checkout, or a bare repo — not an arbitrary directory; expect clone-failed).",
            file=sys.stderr,
        )

    # Does this run actually need egress? Discovery hits GitHub; the public seeds and any remote
    # --repos are network clones. A --no-seeds run over only local paths sends nothing, so it may
    # run offline (Tier 0) — the network gate applies ONLY when real egress is required.
    discovering = args.count > 0 and not repos
    remote_repos = any(not is_local_repo(r) for r in repos)
    needs_network = discovering or (not no_seeds) or remote_repos

    default_tier = "tier1" if needs_network else "tier0"
    cli_net = getattr(args, "network", None) or default_tier
    tier = net.resolve_tier(config_tier=load_repo_config(Path(".")).network_tier, cli=cli_net)
    if needs_network and tier < 1:
        print("corpus-scan needs network tier 1 — it clones remote repos and/or queries GitHub. "
              "Active tier is 0 (DO_NOT_TRACK / --network tier0). For an offline run, pass "
              "--no-seeds with only local --repos paths.", file=sys.stderr)
        return 0

    token = os.environ.get("GH_TOKEN", "")
    if discovering and not token:
        print(
            "warning: GH_TOKEN not set — unauthenticated GitHub Search is 10 req/min "
            "(30 with a token)",
            file=sys.stderr,
        )

    manifest = net.Manifest(tier=tier)
    if needs_network:
        manifest.record(net.EgressOp(
            "corpus-scan", "github.com", "nothing (shallow-clones public repos)", 1,
        ))

    out_dir = Path(args.out) if args.out else Path(f"corpus-out/{today}")
    out_dir.mkdir(parents=True, exist_ok=True)

    report = corpus_scan(
        repos=repos or None, count=args.count, today=today,
        tier=tier, token=token, manifest=manifest, max_repos=args.max_repos,
        use_cache=not args.fresh_corpus, include_seeds=not no_seeds,
    )
    print(manifest.render(), file=sys.stderr)

    md = report_to_markdown(report)
    (out_dir / "corpus-report.md").write_text(md, encoding="utf-8")

    fp_json = json.dumps(
        [dataclasses.asdict(c) for c in report.fp_candidates],
        indent=2, ensure_ascii=False, default=str,
    )
    (out_dir / "fp-candidates.json").write_text(fp_json, encoding="utf-8")

    gap_json = json.dumps(
        [dataclasses.asdict(c) for c in report.gap_candidates],
        indent=2, ensure_ascii=False, default=str,
    )
    (out_dir / "gap-candidates.json").write_text(gap_json, encoding="utf-8")

    (out_dir / "corpus-report.json").write_text(report_to_json(report), encoding="utf-8")

    raw_dir = out_dir / "raw"
    raw_dir.mkdir(exist_ok=True)
    # <org>-<repo> (+ abs-path hash for local repos), computed for the whole batch at once so a
    # residual stem collision is disambiguated rather than silently overwriting a dump: the report
    # says N repos, `raw/` must hold N files.
    for scan, name in zip(report.scanned, unique_raw_scan_names([s.url for s in report.scanned]),
                          strict=True):
        (raw_dir / f"{name}.json").write_text(
            json.dumps(dataclasses.asdict(scan), indent=2, ensure_ascii=False, default=str),
            encoding="utf-8",
        )

    if sys.stdout.isatty():
        print(report_to_terminal(report))
    else:
        print(md)
        print(f"Output written to {out_dir}/")
    return 0


def main(argv: list[str] | None = None) -> int:
    # On Windows the console / redirected stdout defaults to cp1252, which can't encode
    # the ✓ / → / § / 🔴 this CLI prints — force UTF-8 so `agentsec …` works there too
    # (file I/O is pinned to UTF-8 elsewhere; this is the stdout/stderr analogue).
    # Shared with the `scripts/` entry points via `agentsec.console` (#453 review).
    force_utf8_stdio()
    parser = argparse.ArgumentParser(
        prog="agentsec",
        description="Stack-aware security audit for FastAPI + React + Postgres + LLM/RAG apps.",
    )
    parser.add_argument("--version", action="version", version=f"agentsec {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    p_detect = sub.add_parser("detect", help="Fingerprint the target repo's stack")
    p_detect.add_argument("path", nargs="?", default=".", help="Repo path (default: .)")
    p_detect.set_defaults(func=_cmd_detect)

    p_tri = sub.add_parser("trifecta", help="Lethal-trifecta architecture assessment (LLM apps)")
    p_tri.add_argument("path", nargs="?", default=".", help="Repo path (default: .)")
    p_tri.set_defaults(func=_cmd_trifecta)

    p_cov = sub.add_parser("coverage", help="Checklist coverage score card for the detected stack")
    p_cov.add_argument("path", nargs="?", default=".", help="Repo path (default: .)")
    p_cov.add_argument("--format", choices=["markdown", "json", "dashboard"], default="markdown")
    p_cov.add_argument("--out", help="Write the score card to this file instead of stdout")
    p_cov.add_argument(
        "--write-tracker", action="store_true",
        help="Regenerate the generated coverage table in docs/knowledge/checklist-gaps.md (agentsec repo only)",
    )
    p_cov.set_defaults(func=_cmd_coverage)

    p_bom = sub.add_parser("ai-bom", help="AI Bill of Materials: static inventory of the AI supply chain")
    p_bom.add_argument("path", nargs="?", default=".", help="Repo path (default: .)")
    p_bom.add_argument("--format", choices=["json", "cyclonedx", "markdown"], default="json")
    p_bom.add_argument("--out", help="Write the AI-BOM to this file instead of stdout")
    p_bom.set_defaults(func=_cmd_ai_bom)

    p_net = sub.add_parser(
        "network", help="Show the resolved network-egress tier + what would leave your machine",
    )
    p_net.add_argument("path", nargs="?", default=".", help="Repo path (default: .)")
    p_net.add_argument("--network", choices=["tier0", "tier1", "tier2"], metavar="tier0|tier1|tier2")
    p_net.set_defaults(func=_cmd_network)

    # NB: the dependency-CVE monitor is a *maintainer* tool for agentsec's own pins, not
    # a user subcommand — it lives at `python -m agentsec.deps_monitor`, off this surface.

    p_doctor = sub.add_parser("doctor", help="Check which external scanners / live-scan tools are installed")
    p_doctor.add_argument(
        "--canary", action="store_true",
        help="Self-test: prove every static guard detects its planted violation end-to-end (exit 1 on a dead guard)",
    )
    p_doctor.add_argument(
        "--sandbox", action="store_true",
        help="Self-test: prove every guard is import/call-sandboxed (no os/subprocess/network/eval/file-writes; exit 1 on a breach)",
    )
    p_doctor.add_argument(
        "--clean-canary", action="store_true",
        help="Self-test: the negative-direction sibling of --canary — prove every covered guard stays "
             "SILENT on hardened/known-good code (exit 1 on a false positive)",
    )
    p_doctor.add_argument(
        "--efficacy", metavar="PATH", nargs="?", const=".",
        help="Guard efficacy dashboard: show which guards fired against PATH (default: .)",
    )
    p_doctor.add_argument(
        "--check-updates", action="store_true",
        help="Compare the installed registry against versions.json on main (a Tier-1 "
             "unauthenticated fetch — sends nothing about your code or repo; implies --network tier1). "
             "Informational only: never affects findings, never blocks, never sets a "
             "non-zero exit code.",
    )
    p_doctor.add_argument(
        "--network", choices=["tier0", "tier1", "tier2"], metavar="tier0|tier1|tier2",
        help="Network-egress tier for --check-updates (default: tier0 / offline; "
             "--check-updates implies tier1). DO_NOT_TRACK=1 forces tier0.",
    )
    p_doctor.add_argument(
        "--refresh", action="store_true",
        help="With --check-updates: bypass the 24h on-disk cache and re-fetch versions.json.",
    )
    p_doctor.set_defaults(func=_cmd_doctor)

    p_hh = sub.add_parser(
        "harden-host",
        help="Audit the LIVE host's hardening (SSH/UFW/fail2ban/auto-updates/listeners) — read-only, opt-in",
    )
    p_hh.add_argument("--format", choices=["markdown", "summary", "sarif"], default="markdown")
    p_hh.add_argument("--out", help="Write the report to this file instead of stdout")
    p_hh.add_argument(
        "--fail-on", choices=list(SEVERITY_RANK), default="high",
        help="Minimum severity that fails the run (default: high)",
    )
    p_hh.add_argument("--no-fail", action="store_true", help="Always exit 0 (report only)")
    p_hh.add_argument("--top", type=int, metavar="N", help="Show only the N most-severe findings")
    p_hh.set_defaults(func=_cmd_harden_host)

    p_drift = sub.add_parser(
        "drift", help="Compare current findings against a saved snapshot (detect regressions)"
    )
    p_drift.add_argument("path", nargs="?", default=".", help="Repo path (default: .)")
    p_drift.add_argument(
        "--save", action="store_true",
        help="Run audit and save current findings as a new snapshot (creates the baseline)",
    )
    p_drift.add_argument(
        "--snapshot", metavar="FILE",
        help="Snapshot file path (default: <repo>/.agentsec/snapshot.json)",
    )
    p_drift.add_argument(
        "--out", help="Write the drift report to this file instead of stdout",
    )
    p_drift.add_argument(
        "--guards-only", action="store_true",
        help="Skip external scanners when capturing/comparing",
    )
    p_drift.add_argument(
        "--no-fail", action="store_true",
        help="Always exit 0 even when regressions are detected",
    )
    p_drift.set_defaults(func=_cmd_drift)

    p_setup = sub.add_parser("setup", help="Install the scanner toolchain agentsec needs (stack-aware)")
    p_setup.add_argument("path", nargs="?", default=".", help="Target repo (for stack-aware tool selection)")
    p_setup.add_argument("--dry-run", action="store_true", help="Show the plan; install nothing")
    p_setup.add_argument("--all", action="store_true", help="Install every scanner, ignoring the stack N/A rule")
    p_setup.add_argument("--force", action="store_true",
                         help="Reinstall managed pinned tools even when current/ahead/unverifiable "
                              "(recovery for a corrupt binary); never replaces a system install; "
                              "overrides --no-upgrade, so a managed venv whose python tools cannot "
                              "start is still probed and rebuilt (setup does that by default)")
    p_setup.add_argument("--no-upgrade", action="store_true",
                         help="Never upgrade a stale managed tool or rebuild a broken managed venv "
                              "(present tools and the venv are judged by presence only, never run; "
                              "for air-gapped use; --force overrides)")
    p_setup.add_argument("--include-live", action="store_true",
                         help="Also set up live-scan tools (schemathesis; guide docker/psql/jwt_tool)")
    p_setup.add_argument("--suggest-excludes", action="store_true",
                         help="After setup, advise non-product dirs to exclude/demote (advisory)")
    p_setup.set_defaults(func=_cmd_setup)

    p_ci = sub.add_parser("ci", help="Install production-derived, sanitized CI/CD components")
    ci_sub = p_ci.add_subparsers(dest="ci_command", required=True)

    p_ci_list = ci_sub.add_parser("list", help="List components applicable to the detected stack")
    p_ci_list.add_argument("path", nargs="?", default=".", help="Repo path (default: .)")
    p_ci_list.set_defaults(func=_cmd_ci_list)

    p_ci_show = ci_sub.add_parser("show", help="Show a component's manifest + the files it writes")
    p_ci_show.add_argument("component", help="Component id (see `agentsec ci list`)")
    p_ci_show.add_argument("path", nargs="?", default=".", help="Repo path (default: .)")
    p_ci_show.set_defaults(func=_cmd_ci_show)

    p_ci_doctor = ci_sub.add_parser(
        "doctor", help="Preflight the generated agentsec CI workflows (will they run?)",
    )
    p_ci_doctor.add_argument("path", nargs="?", default=".", help="Repo path (default: .)")
    p_ci_doctor.set_defaults(func=_cmd_ci_doctor)

    p_ci_add = ci_sub.add_parser("add", help="Adapt + install one or more components into the target repo")
    p_ci_add.add_argument(
        "components", nargs="+", metavar="component",
        help="One or more component ids (see `agentsec ci list`); an optional trailing repo path (default: .)",
    )
    p_ci_add.add_argument("--force", action="store_true", help="Overwrite existing files / install even if N/A")
    p_ci_add.add_argument("--dry-run", action="store_true", help="Show what would be written; write nothing")
    p_ci_add.add_argument(
        "--path", metavar="SUBDIR", default=".",
        help="Scope the self-audit workflow to a subdir (monorepo module): sets the audit/coverage "
             "target and the trigger paths: filter (default: . = whole repo)",
    )
    p_ci_add.add_argument(
        "--with-baseline", action="store_true",
        help="self-audit only: record current findings as a ratchet snapshot (generated with the "
             "gate's exact flags) and wire --baseline-snapshot in, so existing findings stay "
             "visible in the report and only NEW findings fail the gate",
    )
    p_ci_add.add_argument(
        "--yes", action="store_true",
        help="Accept the --with-baseline snapshot without the interactive HIGH/CRITICAL confirmation "
             "(for CI / non-interactive runs)",
    )
    p_ci_add.add_argument(
        "--install-secret", metavar="SECRET", default="",
        help="Install agentsec with this GitHub secret as the token (e.g. AGENTSEC_PAT). agentsec's "
             "repository is public, so this is only for runners that must authenticate to reach it; "
             "it always installs from agentsec's own repository, never a fork. "
             "The install URL stays token-free; the token reaches git only through GIT_ASKPASS",
    )
    p_ci_add.add_argument(
        "--advisory", action="store_true",
        help="self-audit only: render the action's advisory mode, so it reports every finding (run "
             "summary + SARIF artifact) without failing the build, for a non-blocking rollout",
    )
    p_ci_add.add_argument(
        "--action-sha", metavar="SHA", default="",
        help="self-audit only: the 40-hex commit SHA to pin agentsec's action to. Default: the "
             "commit of this agentsec's release tag, looked up once with `git ls-remote` (your own "
             "git credentials); pass it to skip that lookup, e.g. offline",
    )
    p_ci_add.set_defaults(func=_cmd_ci_add)

    p_ph = sub.add_parser(
        "harden-python", help="Harden a project's Python (uv) deps (cooldown + hashed lock)"
    )
    p_ph.add_argument("path", nargs="?", default=".", help="Repo path (default: .)")
    p_ph.add_argument("--cooldown", type=int, default=48, metavar="HOURS",
                      help="Release-age cooldown to set (default: 48)")
    p_ph.add_argument("--no-lock", action="store_true", help="Only edit config; skip `uv lock`")
    p_ph.add_argument("--scaffold-exceptions", action="store_true",
                      help="Create an empty pip-audit-exceptions.json if missing")
    p_ph.add_argument("--dry-run", action="store_true", help="Show planned changes; write nothing")
    p_ph.set_defaults(func=_cmd_python_harden)

    p_jh = sub.add_parser(
        "harden-js", help="Harden a project's JS/TS (npm/pnpm) deps (cooldown + script-blocking)"
    )
    p_jh.add_argument("path", nargs="?", default=".", help="Repo path (default: .)")
    p_jh.add_argument("--cooldown", type=int, default=48, metavar="HOURS",
                      help="Release-age cooldown to set (default: 48)")
    p_jh.add_argument("--no-allowlist", action="store_true",
                      help="Don't scaffold an empty pnpm build-script allowlist")
    p_jh.add_argument("--dry-run", action="store_true", help="Show planned changes; write nothing")
    p_jh.set_defaults(func=_cmd_js_harden)

    p_fix = sub.add_parser(
        "fix", help="Apply the allowlisted mechanical source fixes (dry-run by default; --write to apply)"
    )
    p_fix.add_argument("path", nargs="?", default=".", help="Repo path (default: .)")
    p_fix.add_argument("--write", action="store_true",
                       help="Apply the fixes (default: dry-run — show diffs, write nothing)")
    p_fix.add_argument("--fix", action="append", metavar="RULE",
                       help="Restrict to specific rule id(s); repeatable (default: all allowlisted)")
    p_fix.set_defaults(func=_cmd_fix)

    p_rg = sub.add_parser(
        "report-gap",
        help="Open a pre-filled GitHub issue to report an uncovered stack gap (or list recorded gaps)",
    )
    p_rg.add_argument(
        "stack", nargs="?", default=None,
        help="Stack to report (e.g. django, flask, prisma, go). "
             "Omit to list all gaps recorded locally.",
    )
    p_rg.add_argument(
        "--open", action="store_true",
        help="Also open the pre-filled issue URL in your browser (default: print only).",
    )
    p_rg.set_defaults(func=_cmd_report_gap)

    p_sx = sub.add_parser(
        "suggest-excludes",
        help="Advise non-product dirs to exclude/demote (advisory; writes nothing unless --write)",
    )
    p_sx.add_argument("path", nargs="?", default=".", help="Repo path (default: .)")
    p_sx.add_argument("--format", choices=["text", "json"], default="text")
    p_sx.add_argument("--write", action="store_true",
                      help="Save accepted suggestions to .agentsec/config.json (interactive unless --yes)")
    p_sx.add_argument("--yes", action="store_true",
                      help="Accept ALL suggestions non-interactively (implies --write; for CI)")
    p_sx.add_argument("--accept", metavar="SEGS",
                      help="Persist ONLY these comma-separated suggested dirs (e.g. old,evals) "
                           "non-interactively; implies --write. A name already covered by config or a built-in "
                           "convention succeeds as a no-op; a name matching nothing exits non-zero.")
    p_sx.set_defaults(func=_cmd_suggest_excludes)

    p_audit = sub.add_parser("audit", help="Run applicable static guards and report")
    _add_audit_args(p_audit)
    _add_enrichment_args(p_audit)
    p_audit.add_argument(
        "--write-baseline", metavar="FILE",
        help="Accept all current findings as exceptions in FILE (only NEW findings surface afterwards). "
             "Implies --deterministic: a baseline is only honest against reproducible findings.",
    )
    p_audit.add_argument(
        "--suggest-excludes", action="store_true",
        help="After the audit, also advise non-product dirs to exclude/demote (reactive; writes nothing)",
    )
    p_audit.add_argument(
        "--save-snapshot", metavar="FILE",
        help="Save current findings as a snapshot JSON for use with 'report --compare'",
    )
    p_audit.add_argument(
        "--baseline-snapshot", metavar="FILE",
        help="Ratchet gate: keep ALL findings in the report but exclude those recorded in this "
             "snapshot (agentsec drift format) from the --fail-on exit, so only findings NEW "
             "since the snapshot fail CI. Unlike --baseline, existing findings stay visible. A "
             "finding the snapshot recorded as superseded history is not exempt once it is live "
             "again (its schema dump went away).",
    )
    p_audit.set_defaults(func=_cmd_audit)

    p_triage = sub.add_parser("triage", help="Classify findings as real/fp/guard-improvement/pending")
    p_triage.add_argument("repo", nargs="?", default=".", help="Repo path (default: .)")
    p_triage.add_argument("--triage-file", metavar="FILE", help="Triage file path (default: <repo>/agentsec-triage.json)")
    # #864: the same selection surface as `audit`, same default (scanners on). Triage
    # classifies the set audit reported; `--guards-only` is the pre-#864 guard-only set.
    _add_scanner_selection_args(p_triage)
    p_triage.add_argument("--guard", metavar="CHECK_ID", help="Only triage findings from this check (a guard id, or a scanner id such as bandit / semgrep / pip-audit)")
    p_triage.add_argument("--rule", metavar="RULE_ID", help="Only triage findings with this exact rule id (a scanner's native rule such as B608 or a semgrep id, or a guard's sub-rule; --dry-run lists it per finding). Composes with --guard/--location/--fingerprint")
    p_triage.add_argument("--location", metavar="PATH", help="Only triage findings AT PATH or beneath it (repo-relative file or directory; anchored, not a substring)")
    p_triage.add_argument("--fingerprint", metavar="FP", help="Only triage findings with this exact stable fingerprint (one fingerprint may collapse same-message findings across lines of one file, never across URL hosts or ports; discover it via --dry-run)")
    p_triage.add_argument("--verdict", choices=["real", "fp", "guard-improvement", "pending"], help="Bulk-set verdict for all untriaged findings")
    p_triage.add_argument("--reason", metavar="TEXT", help="Reason for bulk verdict (used with --verdict fp/guard-improvement)")
    p_triage.add_argument("--improvement", metavar="TEXT", help="Guard improvement hint (used with --verdict guard-improvement)")
    p_triage.add_argument("--triaged-by", metavar="NAME", help="Analyst name to record")
    p_triage.add_argument("--triaged-at", metavar="DATE", help="Triage date (YYYY-MM-DD)")
    p_triage.add_argument("--dry-run", action="store_true", help="Show what would be written without writing")
    p_triage.add_argument(
        "--write-exception",
        nargs="?",
        const="",
        metavar="FILE",
        help="Also emit a matching exception waiver for each fp/guard-improvement verdict "
             "(bridges triage → exceptions; default file: <repo>/agentsec-exceptions.json)",
    )
    p_triage.set_defaults(func=_cmd_triage)

    p_report = sub.add_parser("report", help="Generate triage-aware Markdown security report")
    p_report.add_argument("path", nargs="?", default=".", help="Repo path (default: .)")
    p_report.add_argument("--triage-file", metavar="FILE", help="Triage file path (default: <repo>/agentsec-triage.json)")
    # #864: mirrors `triage` (and `audit`) — a scanner verdict triage wrote must be a row report
    # can show, or the verdict vanishes silently. Ignored under --from-snapshot (the snapshot
    # decides the set; a note says so).
    _add_scanner_selection_args(p_report)
    p_report.add_argument("--from-snapshot", metavar="FILE", help="Use saved snapshot instead of re-scanning")
    p_report.add_argument("--compare", metavar="FILE", help="Compare against a saved snapshot (adds delta section)")
    p_report.add_argument("--out", metavar="FILE", help="Write report to file (default: stdout)")
    p_report.add_argument("--section", metavar="NAME", help="Emit only one report section (e.g. 'summary')")
    p_report.set_defaults(func=_cmd_report)

    p_scan = sub.add_parser(
        "scan",
        help="One-shot: detect + audit → write detect.txt + audit.md + audit.sarif (+ starter exceptions)",
    )
    p_scan.add_argument("path", nargs="?", default=".", help="Repo path (default: .)")
    p_scan.add_argument(
        "--out-dir", default="agentsec-out", metavar="DIR",
        help="Directory for the artifacts (default: agentsec-out)",
    )
    p_scan.add_argument(
        "--setup", action="store_true",
        help="Install the applicable scanner toolchain first (explicit; scan never auto-downloads otherwise)",
    )
    p_scan.add_argument(
        "--guards-only", action="store_true",
        help="Skip the external scanners; run only the dependency-free static guards",
    )
    p_scan.add_argument(
        "--baseline", metavar="FILE",
        help="Exception registry to apply (default: ./agentsec-exceptions.json if present)",
    )
    p_scan.add_argument(
        "--ingest", action="append", metavar="KIND=PATH",
        help="Merge an external report (zap=…, splinter=…, sarif=…). Repeatable.",
    )
    p_scan.add_argument(
        "--fail-on", choices=list(SEVERITY_RANK), default="high",
        help="Minimum severity that fails the run (default: high)",
    )
    p_scan.add_argument("--no-fail", action="store_true", help="Always exit 0 (report only)")
    p_scan.set_defaults(func=_cmd_scan)

    p_live = sub.add_parser(
        "live",
        help="Static audit + live scanners (ZAP / Splinter / Schemathesis / jwt_tool), merged",
    )
    _add_audit_args(p_live)
    # All live scanners need a running target you control.
    p_live.add_argument("--target-url", metavar="URL", help="Run ZAP DAST against this URL")
    p_live.add_argument("--db-url", metavar="DSN", help="Run Supabase Splinter against this Postgres")
    p_live.add_argument(
        "--allow-remote-db", action="store_true",
        help="Permit the Splinter DB lint against a REMOTE database (default: local only; "
             "a remote DSN otherwise needs this flag or an interactive confirm)",
    )
    p_live.add_argument(
        "--allow-remote-target", action="store_true",
        help="Permit INTRUSIVE live scans (--zap-active, Schemathesis fuzzing) against a REMOTE "
             "target (default: hard-refused; only against non-production systems you own)",
    )
    p_live.add_argument(
        "--splinter-sql", metavar="PATH",
        help="Path to splinter.sql (default: fetch the pinned copy unless --no-splinter-fetch)",
    )
    p_live.add_argument(
        "--no-splinter-fetch", action="store_true",
        help="Do not fetch splinter.sql over the network; require --splinter-sql",
    )
    p_live.add_argument(
        "--db-schemas", metavar="LIST",
        help="Comma-list of PostgREST-exposed schemas to lint (e.g. public,workbook). "
             "Default: $PGRST_DB_SCHEMAS, else auto-derived from migration SQL, else public.",
    )
    from agentsec.live import ZAP_IMAGE

    p_live.add_argument("--zap-image", default=ZAP_IMAGE, help=f"ZAP Docker image (default: {ZAP_IMAGE})")
    p_live.add_argument(
        "--zap-active", action="store_true",
        help="Use ZAP's active API scan (sends real attack payloads — intrusive, owned stacks only)",
    )
    p_live.add_argument("--zap-openapi", metavar="URL", help="OpenAPI spec for --zap-active (default: --target-url)")
    p_live.add_argument(
        "--zap-network-host", action="store_true",
        help="Run the ZAP container with --network=host so it reaches 127.0.0.1:PORT directly "
             "(Linux-only; lets --target-url use localhost instead of host.docker.internal)",
    )
    p_live.add_argument("--schemathesis-url", metavar="URL", help="Run Schemathesis fuzzing against this API base URL")
    p_live.add_argument("--schemathesis-skip", metavar="PATH", help="TOML of endpoint patterns to exclude from fuzzing")
    p_live.add_argument("--max-examples", type=int, default=30, help="Schemathesis examples per check (default: 30)")
    p_live.add_argument("--jwt-url", metavar="URL", help="Run jwt_tool against this endpoint")
    p_live.add_argument("--jwt-canary", metavar="TEXT", help="Canary substring present only in successful jwt responses")
    p_live.add_argument("--api-token", metavar="TOKEN", help="Bearer token shared by ZAP-active / Schemathesis / jwt_tool")
    p_live.add_argument("--origin", metavar="ORIGIN", help="Origin header for Schemathesis requests")
    # --- auth bootstrap (mint the bearer token; alternatives to a pre-minted --api-token) ---
    p_live.add_argument(
        "--auth-cmd", metavar="CMD",
        help="Shell command whose stdout is the bearer token (generic auth bootstrap)",
    )
    p_live.add_argument(
        "--supabase-login", action="store_true",
        help="Mint a bearer token via the Supabase password grant (test-user → access_token)",
    )
    p_live.add_argument("--supabase-url", metavar="URL", help="Supabase URL for --supabase-login (default: $SUPABASE_URL)")
    p_live.add_argument("--supabase-anon-key", metavar="KEY",
                        help="Supabase anon key for --supabase-login (default: $SUPABASE_ANON_KEY)")
    p_live.add_argument("--supabase-email", metavar="EMAIL",
                        help="Test-user email for --supabase-login (default: $TEST_USER_EMAIL)")
    p_live.add_argument("--supabase-password", metavar="PASS",
                        help="Test-user password for --supabase-login (default: $TEST_USER_PASSWORD)")
    p_live.add_argument(
        "--zap-rules", metavar="TSV",
        help="ZAP rule-config TSV passed via -c (suppress known-noise alerts per plugin/URL)",
    )
    p_live.add_argument(
        "--garak-target", metavar="URL",
        help="Run garak LLM red-team against this REST endpoint (owned/non-prod targets only)",
    )
    p_live.add_argument(
        "--garak-probes", metavar="LIST",
        help="Comma-separated garak probes (default: promptinject,latentinjection). "
             "Each module is ~256 prompts; more probes = more cost.",
    )
    p_live.add_argument(
        "--garak-generations", type=int, metavar="N",
        help="garak generations per prompt (default: 1). garak's own default is 5; "
             "each generation multiplies the (paid, slow) calls against the target.",
    )
    p_live.add_argument(
        "--promptfoo-config", metavar="PATH", nargs="?", const="promptfooconfig.yaml",
        help="Run promptfoo against this config (bare flag defaults to ./promptfooconfig.yaml)",
    )
    p_live.add_argument(
        "--live-only", "--skip-static", dest="live_only", action="store_true",
        help="Skip the static audit pass entirely; report (and gate on) ONLY the live-scanner "
             "findings (ZAP/Splinter/Schemathesis/jwt/garak/promptfoo). Use for a focused "
             "red-team/DAST run that should not re-surface the whole static audit.",
    )
    p_live.set_defaults(func=_cmd_live)

    p_scanurl = sub.add_parser(
        "scan-live-url",
        help="Outside-in probe of a deployed app's Supabase backend — no repo, no DB DSN required",
    )
    p_scanurl.add_argument("url", metavar="URL", help="The deployed app's https:// URL")
    p_scanurl.add_argument(
        "--verify-token", metavar="TOKEN",
        help="Ownership proof token (omit to get a fresh token + placement instructions; "
             "no probing runs without this)",
    )
    p_scanurl.add_argument(
        "--verify-method", choices=["file", "dns"], default="file",
        help="How --verify-token is checked: a well-known file (default, works anywhere) "
             "or a DNS TXT record (needs dig/nslookup installed)",
    )
    p_scanurl.add_argument(
        "--supabase-url", metavar="URL",
        help="Supabase project URL (default: auto-discovered from the page's own client bundle)",
    )
    p_scanurl.add_argument(
        "--supabase-anon-key", metavar="KEY",
        help="Supabase anon key (default: auto-discovered from the page's own client bundle — "
             "it ships there already, since the browser must read it to make requests)",
    )
    p_scanurl.add_argument(
        "--format", choices=["markdown", "summary", "sarif"], default="markdown",
        help="Report format (default: markdown)",
    )
    p_scanurl.add_argument("--out", metavar="FILE", help="Write the report to FILE instead of stdout")
    p_scanurl.add_argument(
        "--fail-on", choices=list(SEVERITY_RANK), default="high",
        help="Minimum severity that fails the run (default: high)",
    )
    p_scanurl.add_argument("--no-fail", action="store_true", help="Always exit 0 (report only)")
    p_scanurl.set_defaults(func=_cmd_scan_live_url)

    p_corpus = sub.add_parser(
        "corpus-scan",
        help="Scan high-star public repos to surface FP and gap candidates",
    )
    p_corpus.add_argument(
        "--repos", nargs="*", metavar="URL",
        help="Explicit repos to scan — remote clone URLs OR local paths / file:// URLs. The public "
        "seed list is included too unless --no-seeds is given. NOTE: a local repo is scanned at its "
        "committed HEAD — uncommitted working-tree edits are not seen; commit (or stash-then-commit) "
        "first to scan them.",
    )
    p_corpus.add_argument(
        "--repos-file", metavar="PATH",
        help="File of repos to scan, one path/URL per line (# comments + blanks ignored). Merged "
        "with --repos. Use a gitignored file to curate a PRIVATE app corpus (repos you have access "
        "to) without committing their paths into the public seed list. Local repos are scanned at "
        "committed HEAD (see --repos).",
    )
    p_corpus.add_argument(
        "--no-seeds", action="store_true",
        help="Scan ONLY the repos from --repos/--repos-file, skipping the public seed list. With "
        "only local paths this also lets the scan run offline (Tier 0) — no egress.",
    )
    p_corpus.add_argument(
        "--count", type=int, default=10,
        help=(
            "Number of repos to auto-discover via GitHub Search (default: 10) — does NOT "
            "bound the total repo count (the seed list also runs, unless --no-seeds); use "
            "--max-repos for a hard cap. The budget is spread across every search query, so "
            "a run costs one search call per query (set GH_TOKEN to raise the rate limit)"
        ),
    )
    p_corpus.add_argument(
        "--max-repos", type=int, default=None, metavar="N",
        help="Hard ceiling on TOTAL repos cloned per run, seeds prioritized (default: no cap) "
        "— use this for a real small-N/quick run",
    )
    p_corpus.add_argument(
        "--fresh-corpus", action="store_true",
        help="Bypass the local clone cache and re-clone every repo fresh, regardless of cache "
        "age — the periodic/deep-scan mode. Default reuses a cached clone up to 7 days old "
        "(zero network calls on a repeat run); this is what a routine validation scan should use.",
    )
    p_corpus.add_argument(
        "--out", metavar="DIR",
        help="Output directory (default: corpus-out/YYYY-MM-DD/)",
    )
    p_corpus.add_argument(
        "--network", choices=["tier0", "tier1", "tier2"], metavar="tier0|tier1|tier2",
        help="Egress tier (corpus-scan implies tier1 when it needs network; an offline "
        "--no-seeds run over only local paths runs at tier0 / DO_NOT_TRACK=1)",
    )
    p_corpus.set_defaults(func=_cmd_corpus_scan)

    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    sys.exit(main())
