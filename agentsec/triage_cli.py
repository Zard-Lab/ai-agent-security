"""Interactive and bulk triage session driver for `agentsec triage`.

Follows the existing input() + isatty + --yes pattern (suggest-excludes, live consent).
Never uses curses or readline — keeps it portable (Windows CI).

Scope (#864): the set triage classifies is the set `agentsec audit` reports — guards AND the
installed external scanners (bandit, semgrep, pip-audit, ...), selected by the same flags with
the same defaults (`--guards-only`, `--deterministic`, `--network`, `--ingest`). Before acting it
prints a source header (how many findings came from guards vs each scanner, and which scanners
were not installed / offline-skipped / reduced) so a partial toolchain never LOOKS complete.
`--guards-only` restores the pre-#864 guard-only set verbatim.

Non-interactive path (--verdict / --guard / --dry-run):
  agentsec triage <repo> --verdict fp --reason "4xx response — guard too broad"
  agentsec triage <repo> --guard error-info-leak --verdict fp
  # Per-finding selectors (backlog item #5) narrow the bulk set below guard granularity; they compose
  # with --guard and each other. --location is a repo-relative file or directory, ANCHORED at the
  # repo root and boundary-safe (never a substring). --dry-run lists each match's fingerprint so
  # --fingerprint is discoverable:
  agentsec triage <repo> --guard error-info-leak --verdict fp --location app/rag/tools.py
  agentsec triage <repo> --verdict fp --fingerprint <fp-from-dry-run>
  # --rule (#864) is the natural scanner granularity: --guard bandit is the WHOLE scanner and
  # --fingerprint is one file+message; a scanner's rule id sits in between:
  agentsec triage <repo> --guard bandit --rule B101 --verdict fp --reason "asserts in tests"
  agentsec triage <repo> --guards-only --verdict fp --reason "..."   # the pre-#864 guard-only set

Re-emit-only path (backlog item #6): `--write-exception` alone in a non-TTY (no --verdict) skips
classification and re-derives suppression waivers from the already-triaged file — makes the
security-audit skill's triage step fully scriptable:
  agentsec triage <repo> --write-exception   # (piped/CI, no TTY)

Read-only listing (issue #865): a bare non-TTY run (no --verdict, no --write-exception) lists the
untriaged findings with their fingerprints and exits 0 — the same view as --dry-run, so an agent/CI
reader can discover the set (and the fingerprints --fingerprint needs) before choosing a verdict:
  agentsec triage <repo>   # (piped/CI, no TTY) → read-only listing, writes nothing

Interactive path (TTY only):
  Shows each untriaged finding and prompts for verdict.
"""

from __future__ import annotations

import argparse
import sys
from collections import Counter
from datetime import date
from pathlib import Path
from typing import TYPE_CHECKING

from agentsec.findings import location_matches, strip_line_suffix
from agentsec.triage import (
    VERDICT_VALUES,
    AnnotatedFinding,
    TriageVerdict,
    apply_triage,
    fingerprint,
    load_triage,
    save_triage,
)

if TYPE_CHECKING:
    from agentsec.audit import AuditResult

# Verdicts that become suppression waivers when `--write-exception` is set.
_WAIVABLE_VERDICTS = ("fp", "guard-improvement")


def source_lines(result: AuditResult, *, scanners_ran: bool) -> list[str]:
    """The source header `triage` prints (and `report` echoes to stderr) before acting (#864).

    Two disclosures, both Rule 3 ("a failure that presents as success"):
    - the ORIGIN MIX: how many findings came from agentsec's own guards vs each external
      scanner (and ingested reports). A bulk verdict with no `--guard` is an "everything"
      selector, so the operator must see that "everything" now includes bandit's 27k rows
      before an `fp` verdict becomes 27k waivers;
    - the SCANNERS THAT DID NOT RUN, or ran reduced: not installed, offline-skipped below
      the network tier, reduced rule set, errored. Without this an offline machine's triage
      is indistinguishable from a complete one, and "All findings already triaged" is then
      a claim about a set that was never scanned.
    The counts partition on the REGISTRY (`ALL_RUNNERS` ids), not on `rule`, so an ingested
    finding (`sarif:zap`, `zap`, `splinter`) is neither a guard nor a scanner and is named
    as ingested."""
    from agentsec.registry import ALL_RUNNERS, check_meta

    runner_ids = {r.id for r in ALL_RUNNERS}
    per_scanner: Counter[str] = Counter()
    guards = ingested = 0
    for f in result.findings:
        if f.check_id in runner_ids:
            per_scanner[f.check_id] += 1
        elif check_meta(f.check_id) is not None:
            guards += 1
        else:
            ingested += 1
    total = len(result.findings)
    parts = [f"{guards} from guards"]
    if scanners_ran:
        breakdown = ", ".join(f"{k} {n}" for k, n in sorted(per_scanner.items()))
        parts.append(
            f"{sum(per_scanner.values())} from external scanners"
            + (f" ({breakdown})" if breakdown else "")
        )
    else:
        parts.append("external scanners not run (--guards-only)")
    if ingested:
        parts.append(f"{ingested} ingested")
    lines = [f"{total} finding(s): " + ", ".join(parts)
             + ("  [--guards-only to exclude scanners]" if scanners_ran and per_scanner else "")]
    if result.tools_unavailable:
        lines.append(f"  scanners not installed (skipped): {', '.join(result.tools_unavailable)}")
    if result.tools_offline_skipped:
        lines.append("  scanners skipped (offline — raise --network to enable): "
                     f"{', '.join(result.tools_offline_skipped)}")
    for note in result.tools_reduced:
        lines.append(f"  reduced coverage: {note}")
    if result.tools_errored:
        lines.append(f"  scanners that errored: {', '.join(result.tools_errored)}")
    if (unparsed := result.unparsed_python_notice()) is not None:  # #1001
        lines.append(f"  {unparsed[0][0].lower()}{unparsed[0][1:]}: {unparsed[1]}")
    return lines


# A location is "path", "path:line", "path:line:col" — or, for an ingested ZAP/live finding, a
# URL. Only a TRAILING numeric line/col suffix of a NON-URL may be stripped: `split(":")[0]`
# turned `https://app.example.com/admin` into `"https"`, and because `Exception_.matches` falls
# back to a boundary PREFIX match, a waiver written for one ZAP finding at `/admin` then
# suppressed an unrelated CRITICAL at `/checkout` — a different message and a different severity
# (#474 review). The rule now lives ONCE in `findings.split_line_suffix`: it was duplicated here
# and at `stable_fingerprint`, and the copy that lacked the URL guard ate a port (#567).
def _location_file(location: str) -> str:
    """The file/URL part of a finding location, with any trailing `:line[:col]` removed.

    A URL is returned WHOLE. `scheme://host:9200` ends in the same `:<digits>` a `path:line`
    does, and stripping it ate the PORT: the waiver written for a finding at
    `https://host:9200` landed on `https://host`, which `location_matches` then read as a
    boundary prefix and used to suppress an unrelated finding at `https://host:6379` — a
    different port, message and severity (#474 gate). The `://` test is the one
    `normalize_location` already uses to decide a location is not a filesystem path, so the
    two functions agree on what a URL is. A URL that really does carry a line suffix
    (a SARIF result with both a URL `uri` and a `startLine`) keeps it, so its waiver is
    line-pinned rather than whole-file: narrower, which is the safe direction here."""
    if not location:
        return ""
    return strip_line_suffix(location)


def run(args: argparse.Namespace) -> int:
    # `_ingest_findings` / `_resolve_network` are the SAME converters `_cmd_audit` uses, so
    # triage cannot drift from audit's selection semantics (the whole point of #864: the triage
    # set IS the audit set). `_resolve_network` reads every optional flag through getattr, so a
    # bare Namespace (the test double) is fine.
    from agentsec.audit import audit
    from agentsec.cli import _ingest_findings, _resolve_network

    repo = Path(args.repo)
    triage_path = Path(args.triage_file) if args.triage_file else repo / "agentsec-triage.json"

    # #864: scanners run by default, exactly as `agentsec audit` does. Before this the call was
    # `audit(repo, run_scanners=False)`, hard-coded since triage's first commit, so bandit /
    # semgrep / pip-audit findings could never be classified or waived here and every scanner FP
    # went into a `# nosec` / `# nosemgrep` — a permanent ignore with no `review_by`, the exact
    # silent forever-ignore the exception layer exists to prevent. A missing binary still
    # degrades to *skipped* (and is disclosed in the header below), never to a failure.
    scanners_ran = not getattr(args, "guards_only", False)
    tier, _kev, _epss = _resolve_network(args, repo)
    result = audit(
        repo,
        run_scanners=scanners_ran,
        extra_findings=_ingest_findings(getattr(args, "ingest", None)),
        network_tier=tier,
        deterministic=bool(getattr(args, "deterministic", False)),
    )
    findings = result.findings

    # Printed BEFORE the empty check: "No findings to triage." on a machine where every scanner
    # was skipped is the quiet failure the header exists to expose.
    for line in source_lines(result, scanners_ran=scanners_ran):
        print(line)

    if not findings:
        print("No findings to triage.")
        return 0

    verdicts = load_triage(triage_path)
    annotated = apply_triage(findings, verdicts)

    guard_filter: str | None = getattr(args, "guard", None)
    # `is not None`, NOT truthiness (see the --location note below). Truthiness meant `--guard ""`
    # skipped the filter entirely and the bulk verdict hit every untriaged finding. The comparison
    # is an equality test, so an empty selector now matches nothing and exits without writing.
    if guard_filter is not None:
        annotated = [a for a in annotated if a.finding.check_id == guard_filter]
        if not annotated:
            print(f"No findings for guard '{guard_filter}'.")
            return 0

    # --rule (#864): equality on `finding.rule`, the scanner's native rule id (`B608`, a semgrep
    # id, a CVE) or a guard's sub-rule. Composes with the other selectors. The empty selector
    # needs one more guard than `--guard ""` did: plain equality would make `--rule ""` (an unset
    # shell variable) select every finding whose rule IS empty — every guard finding without a
    # sub-rule, i.e. most of them — which is the #474 over-match in a new coat. So an empty rule
    # selector matches nothing, like the other three, and exits without writing.
    rule_filter: str | None = getattr(args, "rule", None)
    if rule_filter is not None:
        annotated = [a for a in annotated if rule_filter and a.finding.rule == rule_filter]
        if not annotated:
            print(f"No findings for rule '{rule_filter}'.")
            return 0

    # Per-finding selectors (backlog item #5): narrow the bulk set below guard granularity so a
    # guard whose findings split across files/rules can be triaged non-interactively. Both compose
    # with --guard and with each other; an empty match exits cleanly (like --guard) not writing.
    #
    # INVARIANT: `--location V` selects finding F iff F's location IS V or lies strictly beneath
    # it (the `/` directory boundary or the `:line[:col]` boundary). Anchored and boundary-safe,
    # never substring containment, and a degenerate V selects nothing. This is a SUPPRESSION path
    # (an fp verdict becomes a waiver), so it shares the one matching rule with the other
    # suppression selector, `exceptions.py::Exception_.matches`: `findings.location_matches`.
    #
    # Two rounds of this were fixed by special-casing the value instead of the rule. `--location ""`
    # was first "fixed" by `is not None`, which changed which BRANCH ran, not the outcome, because
    # `"" in s` is True for every s. It was then "fixed" by returning [] for the empty string, which
    # left the substring test in place for every other value: verified against a real repo, an
    # unremarkable `--location "."` (this repo's own python-supply-chain guard emits a finding whose
    # location IS `.`, and `dirname` of any repo-root file returns `.`) waived ALL 10 findings
    # including 3 HIGH cors-wildcard; `--location app` waived `application/svc.py` too; and
    # `--location "pp/main.py"` matched `app/main.py` mid-string. Derive from the invariant
    # (#474 re-review, 2026-07-31).
    #
    # Anchoring is a real narrowing: a bare basename or a path suffix no longer selects. Locations
    # are repo-root-relative, so pass the repo-relative path (`app/rag/tools.py`, not `rag/tools.py`)
    # or use --fingerprint, which --dry-run prints, for the exact per-finding pin.
    location_filter: str | None = getattr(args, "location", None)
    if location_filter is not None:
        annotated = [a for a in annotated if location_matches(location_filter, a.finding.location)]
        if not annotated:
            print(f"No findings matching location '{location_filter}'.")
            return 0

    fingerprint_filter: str | None = getattr(args, "fingerprint", None)
    if fingerprint_filter is not None:      # equality, so an empty selector already matches nothing
        annotated = [a for a in annotated if fingerprint(a.finding) == fingerprint_filter]
        if not annotated:
            print(f"No finding with fingerprint '{fingerprint_filter}'.")
            return 0

    bulk_verdict: str | None = getattr(args, "verdict", None)
    dry_run: bool = getattr(args, "dry_run", False)
    # None = flag absent; "" = flag given without a path (use default); str = explicit path.
    write_exception: str | None = getattr(args, "write_exception", None)

    if bulk_verdict:
        if bulk_verdict not in VERDICT_VALUES:
            print(
                f"Invalid verdict '{bulk_verdict}'. Choose from: {', '.join(sorted(VERDICT_VALUES))}",
                file=sys.stderr,
            )
            return 1
        rc = _bulk_triage(annotated, bulk_verdict, args, verdicts, triage_path, dry_run)
    elif not sys.stdin.isatty():
        # Backlog item #6: `--write-exception` alone in a non-TTY re-derives waivers from the already-
        # triaged file instead of erroring — there is no verdict to classify, the intent is pure
        # (re)emit. Return here so the shared bridge below does not double-run the derivation.
        if write_exception is not None:
            if dry_run:
                print(f"--dry-run: would re-emit exception waivers from {triage_path}")
                return 0
            _write_exceptions_from_triage(triage_path, repo, write_exception)
            return 0
        # Issue #865: a non-TTY run with neither --verdict nor --write-exception requested no
        # mutation, so it is a READ-ONLY query, not an error. Default to the --dry-run listing
        # (untriaged findings + their fingerprints) and exit 0 so an agent/CI reader can discover
        # the finding set and pass --fingerprint/--verdict next. Nothing is written on this path —
        # it returns before the write-exception bridge below.
        pending = [a for a in annotated if a.verdict is None]
        if not pending:
            print("All findings already triaged.")
            return 0
        print(
            f"{len(pending)} untriaged finding(s). Pass --verdict for bulk triage, narrowing with "
            f"--guard/--location, or --fingerprint <fp> to target one exactly (fingerprints below):"
        )
        _print_untriaged_lines(annotated)
        return 0
    else:
        rc = _interactive_triage(annotated, verdicts, triage_path, dry_run)

    # Bridge (issue #325): once verdicts are on disk, derive matching exception waivers.
    # Skip on failure or --dry-run (nothing was written to derive from).
    if rc == 0 and write_exception is not None and not dry_run:
        _write_exceptions_from_triage(triage_path, repo, write_exception)
    return rc


def _write_exceptions_from_triage(triage_path: Path, repo: Path, dest: str) -> None:
    """Derive exception waivers from the triage file's fp/guard-improvement verdicts and
    merge them into the exceptions registry (issue #325). Each waiver carries the verdict's
    stable fingerprint, which matches the finding via `Exception_.matches`.

    No pruning: every current fp/guard-improvement verdict is re-emitted each run. A waiver
    whose fingerprint no longer matches any live finding (fixed, or a stale pre-#325 verdict)
    is inert and is not actively removed.

    This used to add "and self-cleans via `review_by` expiry". It does not: expiry does not
    clean a dead entry, it re-surfaces it as a lapse reminder asking a human to re-decide a
    question that no longer exists (issue #730). Removal is still the operator's call — an
    entry is an accepted-risk record, not cache — but the audit footer now NAMES the entries
    that matched nothing while their check ran, so the decision is at least offered."""
    from agentsec.exceptions import merge_exceptions

    verdicts = load_triage(triage_path)
    # `rule` and `location` here are DESCRIPTIVE, not selectors. `v.file` is the
    # line-STRIPPED path, so as a selector it would mean "this whole file, for this rule" —
    # far broader than the single finding the verdict was about. `Exception_.matches`
    # decides on the `fingerprint` alone whenever one is present (#507), so these two
    # fields never widen the waiver; they are kept because they are what makes an entry
    # readable in the registry and what the lapse reminder names.
    entries: list[dict[str, str]] = [
        {
            "rule": v.guard_id,
            "location": v.file,
            "fingerprint": v.fingerprint,
            "reason": v.reason or f"triaged {v.verdict}",
        }
        for v in verdicts
        if v.verdict in _WAIVABLE_VERDICTS
    ]
    exc_path = Path(dest) if dest else repo / "agentsec-exceptions.json"
    # merge_exceptions refuses (raises) rather than clobber a malformed registry — the verdicts are
    # already saved, so degrade to a warning instead of failing the whole triage run.
    try:
        added = merge_exceptions(exc_path, entries, date.today())
    except ValueError as e:
        print(f"warning: {e}; no exception waivers written", file=sys.stderr)
        return
    print(f"Wrote {added} new exception waiver(s) → {exc_path} (from {len(entries)} waivable verdict(s))")


def _print_untriaged_lines(annotated: list[AnnotatedFinding]) -> None:
    """List each untriaged finding as `<fingerprint>  <check_id>  <rule>  <location>`.

    Shared by the `--dry-run` bulk listing and the non-TTY read-only default (issue #865) so
    the two views cannot drift. The fingerprint is surfaced nowhere else, and `--fingerprint
    <fp>` needs it (backlog item #5); the rule column (#864) does the same for `--rule` — a
    scanner's rule id is the selector between "the whole scanner" and "one file+message"
    (`-` when a guard leaves its rule unset).
    """
    for a in annotated:
        if a.verdict is None:
            print(
                f"  {fingerprint(a.finding)}  {a.finding.check_id}  "
                f"{a.finding.rule or '-'}  {a.finding.location}"
            )


def _bulk_triage(
    annotated: list[AnnotatedFinding],
    verdict_value: str,
    args: argparse.Namespace,
    verdicts: list[TriageVerdict],
    triage_path: Path,
    dry_run: bool,
) -> int:

    reason = getattr(args, "reason", "") or ""
    improvement = getattr(args, "improvement", "") or ""
    triaged_by = getattr(args, "triaged_by", "") or ""
    triaged_at = getattr(args, "triaged_at", "") or ""

    index: dict[str, TriageVerdict] = {v.fingerprint: v for v in verdicts}
    updated = 0
    for a in annotated:
        if a.verdict is not None:
            continue
        fp = fingerprint(a.finding)
        new_verdict = TriageVerdict(
            guard_id=a.finding.check_id,
            file=_location_file(a.finding.location) if a.finding.location else "",
            fingerprint=fp,
            verdict=verdict_value,
            rule=a.finding.rule,
            reason=reason,
            improvement=improvement,
            triaged_by=triaged_by,
            triaged_at=triaged_at,
        )
        index[fp] = new_verdict
        updated += 1

    if dry_run:
        print(f"--dry-run: would write {updated} new verdict(s) to {triage_path}")
        # List each matched untriaged finding with its fingerprint so `--fingerprint` is
        # discoverable (backlog item #5): the fingerprint is otherwise not surfaced anywhere.
        _print_untriaged_lines(annotated)
        return 0

    save_triage(list(index.values()), triage_path)
    print(f"Wrote {updated} new verdict(s) to {triage_path}")
    return 0


def _interactive_triage(
    annotated: list[AnnotatedFinding],
    verdicts: list[TriageVerdict],
    triage_path: Path,
    dry_run: bool,
) -> int:

    pending = [a for a in annotated if a.verdict is None]
    if not pending:
        print("All findings already triaged.")
        return 0

    index: dict[str, TriageVerdict] = {v.fingerprint: v for v in verdicts}
    print(f"{len(pending)} finding(s) to triage. Type verdict or '?' for help. Ctrl+C to stop.")
    print("Verdicts: real | fp | guard-improvement | pending | skip (s)")
    print()

    for i, a in enumerate(pending, 1):
        f = a.finding
        # Show the rule when it adds information (a scanner's `B608`, a guard's sub-rule);
        # a guard whose rule IS its id would just repeat itself.
        rule_note = f" [{f.rule}]" if f.rule and f.rule != f.check_id else ""
        print(f"[{i}/{len(pending)}] {f.check_id}{rule_note}  {f.location}")
        print(f"  {f.title}: {f.message or f.remediation or ''}")
        try:
            raw = input("  verdict> ").strip().lower()
        except (KeyboardInterrupt, EOFError):
            print()
            break

        if raw in ("s", "skip", ""):
            continue
        if raw == "?":
            print("  real=confirmed security issue  fp=false positive  guard-improvement=fp+improvement  pending=seen not decided")
            continue
        if raw not in ("real", "fp", "guard-improvement", "pending"):
            print(f"  Unknown verdict '{raw}' — skipping")
            continue

        reason = ""
        improvement = ""
        if raw in ("fp", "guard-improvement"):
            reason = input("  reason> ").strip()
            if raw == "guard-improvement":
                improvement = input("  improvement hint> ").strip()

        fp_hash = fingerprint(f)
        index[fp_hash] = TriageVerdict(
            guard_id=f.check_id,
            file=_location_file(f.location),
            fingerprint=fp_hash,
            verdict=raw,
            rule=f.rule,
            reason=reason,
            improvement=improvement,
        )

    if dry_run:
        print(f"--dry-run: would write {len(index)} verdict(s) to {triage_path}")
        return 0

    save_triage(list(index.values()), triage_path)
    print(f"Saved {len(index)} verdict(s) to {triage_path}")
    return 0
