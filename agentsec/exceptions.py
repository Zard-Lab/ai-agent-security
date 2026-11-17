"""Exception / baseline registry — accept findings with an expiring decision.

Mirrors the donor's exception-registry-with-`review_by` pattern (no silent
forever-ignores). An exception suppresses a matching finding **only while it is
active**; once `review_by` passes, the exception lapses, the finding re-surfaces
(forcing a re-decision), and a reminder is recorded.

Registry file (JSON, default `agentsec-exceptions.json` at the repo root):

    {
      "exceptions": [
        {"rule": "frontend-xss/dangerously-set-inner-html",
         "location": "src/Comment.tsx:42",
         "reason": "sanitized via DOMPurify before render",
         "review_by": "2026-09-01"}
      ]
    }

Matching: `rule` matches the finding's `rule` OR `check_id`. `location` is
optional (omitted = the whole rule); otherwise an exact match or a boundary-safe
path prefix (so `src/legacy/` accepts everything under it, but never `src/legacy2/`);
see `findings.location_matches`. `review_by` omitted = no expiry.

Project-local suppressions (`.agentsec/suppress.json`, loaded via
`load_local_exceptions`) use the SAME format but `review_by` is **required**: an
undated local entry is not honored (the finding re-surfaces with a reminder).
The asymmetry is deliberate — the global registry is ours and may hold permanent
Tier-A entries; a repo's local file is team-authored FP triage and must expire.
"""
from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path

from agentsec.findings import Finding, location_matches, sanitize_finding, strip_line_suffix

DEFAULT_REGISTRY = "agentsec-exceptions.json"
# Default review_by window for write_baseline (`audit --write-baseline`, `ci add --with-baseline`):
# an accepted baseline lapses after this many days and re-surfaces, forcing a deliberate re-review
# rather than a forever-ignore. 30d keeps the re-review cadence tight; overridable per call via
# write_baseline(ttl_days=...). Note: this is NOT the 90-day coordinated-disclosure window.
DEFAULT_TTL_DAYS = 30

# How many dead waivers each disclosure channel (`ExceptionOutcome.unused_waivers`,
# `ExceptionOutcome.drifted_waivers`) names individually before it collapses the tail into a
# count. The footer is a disclosure, not a work queue: a registry with 150 dead entries needs
# to say so in one line, not push 150 lines past everything else in the report. The tail is
# COUNTED, never silently dropped.
_UNUSED_WAIVER_CAP = 10


def owning_check(rule: str) -> str:
    """The check id a waiver's `rule` is scoped to, as best it can be resolved.

    `rule` carries several conventions depending on which writer produced the entry:
    the bare `check_id` (the triage bridge, `triage_cli.py`), `"<check_id>/<sub-rule>"`
    (`write_baseline` over a guard finding), or a scanner-NATIVE rule like `B608`
    (`write_baseline` over a runner finding — it keeps bandit's `test_id` and drops the
    runner id entirely). The first two resolve by taking the head; the third resolves to
    a token that is not a check id at all, and every caller must then stay silent rather
    than guess.

    **The head is not always the owning check.** `agent-memory-security` emits
    `rule="agent-memory/..."` and `mcp-config-security` emits `rule="mcp-config/..."`, so
    the head is a truncated prefix that matches no registered id and both guards resolve as
    unattributable. That is the safe direction (their dead waivers go unreported rather than
    live ones being called dead), but it is a real gap, not the intended behavior — tracked
    as issue #734, and pinned by `test_owning_check_resolves_every_guards_real_rule_prefix`
    so a THIRD guard cannot drift in unnoticed.

    That "unresolvable → say nothing" fall-back is load-bearing for issue #730: it is what
    keeps a `--guards-only` run from declaring every scanner-scoped waiver dead. Measured
    on the issue's reproduction, it is the difference between 2 correct lines and 10."""
    return rule.split("/", 1)[0]


@dataclass
class Exception_:
    rule: str = ""
    location: str = ""
    reason: str = ""
    review_by: str = ""
    fingerprint: str = ""
    local: bool = False  # from a repo's .agentsec/suppress.json (review_by REQUIRED — see apply_exceptions)

    def matches(self, f: Finding) -> bool:
        # A `fingerprint` IS the entry's identity: when one is present it DECIDES, and we
        # never fall through to the coarser rule/location form (issue #507).
        #
        # A stored fingerprint may be the line-SENSITIVE `Finding.fingerprint()` (as
        # written by `write_baseline`) OR the line-INSENSITIVE `stable_fingerprint()`
        # (as carried by a waiver bridged from a triage verdict, issue #325). Accept
        # either. A bridged stable-fp waiver still intentionally suppresses every finding
        # in that file sharing the same rule+message across ALL lines — the same collapse
        # `triage.fingerprint()` documents (deliberate: a verdict is a per-issue call).
        # `apply_exceptions` now COUNTS that breadth so it cannot happen silently.
        #
        # The fall-through this replaces was the #507 defect. The triage bridge writes
        # `rule` + a line-STRIPPED `location` + `fingerprint` into one entry, and an
        # OR meant the entry ALSO matched every finding of that rule anywhere in that
        # FILE — including findings with a different fingerprint that were never triaged.
        # Measured: one `fp` verdict on one secret suppressed a second, unrelated live
        # secret. `write_baseline` was never exposed (it writes a full `path:line:col`),
        # which is why the registry's own 151 entries are unaffected by this change.
        if self.fingerprint:
            return self.fingerprint in (f.fingerprint(), f.stable_fingerprint())
        if not self.rule or self.rule not in (f.rule, f.check_id):
            return False
        if not self.location:
            return True
        # Boundary-safe prefix: a bare-file or directory exception covers a finding beneath it
        # when the next char is a path `/` OR a line `:` separator, so `guards/foo.py` covers
        # `guards/foo.py:12` and `src/legacy` covers `src/legacy/x.py` but NOT `src/legacy2/...`.
        # The `:` boundary is what restores bare-file exceptions (without it a `guards/foo.py`
        # entry never matched a per-line finding). Shared with `triage --location`, the other
        # location selector on the suppression path, so both waive the same set (see the helper).
        return location_matches(self.location, f.location)

    def key(self) -> tuple[str, str, str]:
        """The entry's identity triple, the same one `merge_exceptions` de-dupes on (#507).

        One definition shared by the broad-waiver counter and the unused-waiver
        complement, so both talk about a waiver in exactly the same terms."""
        return (self.fingerprint, self.rule, self.location)

    def lapsed(self, today: date) -> bool:
        if not self.review_by:
            return False
        try:
            return date.fromisoformat(self.review_by) < today
        except ValueError:
            return False  # malformed date → treat as no-expiry (won't silently lapse)


@dataclass
class ExceptionOutcome:
    kept: list[Finding] = field(default_factory=list)
    suppressed: list[Finding] = field(default_factory=list)
    lapsed: list[str] = field(default_factory=list)  # human-readable reminders
    local_suppressed: list[Finding] = field(default_factory=list)  # subset of `suppressed` from suppress.json
    # How many findings each APPLIED waiver actually suppressed, keyed by the entry's
    # identity triple `(fingerprint, rule, location)` — the same key `merge_exceptions`
    # dedupes on (issue #507). A waiver is written about ONE finding; when it suppresses
    # several, the extras are real findings that went quiet, and the report has to say so.
    # Only entries that suppressed at least one finding appear (a lapsed or undated-local
    # entry re-surfaces its findings, so it suppressed nothing) — which is exactly why this
    # is NOT the right basis for the unused-waiver complement; see `matched_keys` below.
    waiver_counts: dict[tuple[str, str, str], int] = field(default_factory=dict)
    # Every entry supplied to this run, and every entry that matched SOMETHING (issue #730).
    # The complement `considered_keys - matched_keys` is the set of waivers that matched no
    # finding at all — the thing `waiver_counts` structurally cannot express, because it is
    # keyed off findings and an entry matching zero findings is never visited.
    #
    # `matched_keys` is deliberately a SUPERSET of `waiver_counts`: a lapsed or undated-local
    # entry matched its finding and then declined to honor it, so it is live, not dead.
    # Complementing against `waiver_counts` instead would report every expired waiver as an
    # unused one — the first trap in this area, and the reason these are two fields.
    considered_keys: set[tuple[str, str, str]] = field(default_factory=set)
    matched_keys: set[tuple[str, str, str]] = field(default_factory=set)
    # Every live finding that matched NO entry at all (issue #896). A subset of `kept`, which
    # also holds lapsed and undated-local re-surfacings; those matched an entry, so they are
    # not evidence that some OTHER entry lost its finding. `_dead_waivers` joins a dead
    # entry's `(rule, location)` against this list to tell "the finding is gone" apart from
    # "the finding is right here under a new fingerprint". Disclosure only: nothing reads it
    # to decide suppression.
    unwaived: list[Finding] = field(default_factory=list)

    def _drift_candidates(self, rule: str, location: str) -> list[Finding]:
        """Unwaived live findings at a dead entry's own rule + location (issue #896).

        Matches the entry's `rule` the way `Exception_.matches` does (`rule` or `check_id`),
        and its `location` either exactly (a `write_baseline` entry: `path:line:col`) or with
        the live line suffix stripped (a triage-bridged entry stores the bare path)."""
        return [
            f for f in self.unwaived
            if rule in (f.rule, f.check_id)
            and (f.location == location or strip_line_suffix(f.location) == location)
        ]

    def _dead_waivers(
        self, ran: frozenset[str], out_of_scope: Callable[[str], bool] | None
    ) -> tuple[int, list[tuple[tuple[str, str, str], list[Finding]]], list[tuple[str, str, str]]]:
        """Every waiver that matched NOTHING while its check ran, split into two classes.

        Returns `(judgeable, drifted, unused)`: the size of the population this run could
        judge at all (the scan-root ratio's denominator), the dead entries whose finding is
        still present under a new identity (each with its live candidates), and the rest.
        `unused_waivers()` and `drifted_waivers()` render the two classes as separate report
        channels, so a still-live accepted-risk record is never labelled "unused" (#896).

        `ran` is the set of check ids that actually executed this scan. An entry is judged
        only when its owning check is in that set, so a waiver is never called dead merely
        because its check did not run: `--guards-only` leaves every runner out of `ran`, and
        a scanner-native rule (`B608`) resolves to no check id at all. Measured on the #730
        reproduction, that gate is the difference between 2 correct lines and 10.

        `out_of_scope(location)` filters out waivers pointing at paths this run dropped before
        the registry ever saw them (`--exclude`, a configured archive tree). Those matched
        nothing because their findings were removed, not because they are dead. It is a
        per-waiver test rather than a whole-run kill-switch on purpose: excluding one tree must
        not silence the disclosure for every OTHER waiver, or the feature would be off for most
        real runs — agentsec's own self-audit passes `--exclude` too."""
        def judgeable(k: tuple[str, str, str]) -> bool:
            """Could THIS run have formed an opinion about this entry at all?

            An empty owner is checked explicitly rather than left to fail the `in ran` test:
            a fingerprint-only entry carries no `rule`, and "no check id" must mean "say
            nothing" by construction, not by the accident that no registered check happens
            to have an empty id today."""
            owner = owning_check(k[1])
            if not owner or owner not in ran:
                return False
            return not (out_of_scope is not None and out_of_scope(k[2]))

        # The judgeable population is BOTH the filter and the denominator below. Scoring the
        # dead count against the raw registry size instead lets unattributable entries dilute
        # the ratio: a scanner-heavy registry on a `--guards-only` run can be a 100% miss on
        # everything this run could actually judge and still fall under the threshold, so the
        # one signal that would make a rushed user stop and check their scan root goes quiet
        # in exactly the case it exists for (PR #733 review, High).
        can_judge = {k for k in self.considered_keys if judgeable(k)}
        # Split the dead entries (issue #896). A fingerprinted entry whose own rule + location
        # still has an unwaived live finding did not lose its finding; the finding changed
        # identity under it (the fingerprint basis includes the message head, so a reworded
        # guard message is enough). Calling that one "candidate to remove" steers the user to
        # delete an accepted-risk record for a finding that is plainly still present. An entry
        # with no fingerprint cannot land here: its rule/location match would have caught it.
        drifted: list[tuple[tuple[str, str, str], list[Finding]]] = []
        unused: list[tuple[str, str, str]] = []
        for k in sorted(can_judge - self.matched_keys):
            fingerprint, rule, location = k
            candidates = self._drift_candidates(rule, location) if fingerprint and rule and location else []
            if candidates:
                drifted.append((k, candidates))
            else:
                unused.append(k)
        return len(can_judge), drifted, unused

    def unused_waivers(
        self, ran: frozenset[str], out_of_scope: Callable[[str], bool] | None = None
    ) -> list[str]:
        """Rendered lines for every waiver that matched NOTHING while its check ran (#730).

        The mirror of `broad_waivers()`: that one asks "is this waiver too broad", this one
        asks "does this waiver still cover anything". Without it a waiver whose finding was
        fixed at source is invisible by construction — it lands in no outcome field — until
        its `review_by` passes, at which point the ONLY channel that ever mentions it is a
        lapse reminder asking a human to re-decide a question that no longer exists.

        The wording stops at what is known. "Matched nothing while the check ran" is
        observed; "the finding was fixed" is an inference, and a shadowed duplicate entry
        (`apply_exceptions` stops at the FIRST matching waiver) reaches here for a completely
        different reason. Empty list = every waiver still covers something.

        A dead entry whose finding is still present under a new fingerprint is NOT listed
        here: it is `drifted_waivers()`'s, and the report labels it separately, because the
        advice for it is the opposite of this channel's "candidate to remove" (#896). See
        `_dead_waivers()` for the `ran` and `out_of_scope` gates both channels share."""
        judged, _, unused = self._dead_waivers(ran, out_of_scope)
        if not unused:
            return []
        out: list[str] = []
        # A registry whose locations no longer line up with the scan root leaves EVERY entry
        # unmatched, and every owning check still ran — so the gate passes and the report
        # confidently tells the user to delete their whole baseline. Measured: rooting
        # agentsec's own self-audit one directory too high turned 153/153 entries "dead".
        # A wholesale miss is far more likely to be a misaimed scan than 153 real fixes, so
        # say that first rather than enumerating a list that is probably wrong. Drifted entries
        # stay in the denominator but out of the numerator: their locations DO line up (that is
        # how they were classified), so a mass message reword must not be blamed on the scan root.
        if judged >= 4 and len(unused) * 2 >= judged:
            out.append(
                f"{len(unused)} of {judged} waivers this run could check matched nothing — if you "
                "did not just fix that many findings, check that the scan root matches the one the "
                "registry was written against (a moved/re-rooted tree invalidates every location at once)"
            )
        for fingerprint, rule, location in unused[:_UNUSED_WAIVER_CAP]:
            what = rule or fingerprint or "(unnamed)"
            where = f" @ {location}" if location else ""
            out.append(
                f"waiver for {what}{where} matched nothing and its check ran — "
                "candidate to remove (re-confirm before deleting: it is an accepted-risk record)"
            )
        if len(unused) > _UNUSED_WAIVER_CAP:
            out.append(f"…and {len(unused) - _UNUSED_WAIVER_CAP} more waiver(s) that matched nothing")
        return out

    def drifted_waivers(
        self, ran: frozenset[str], out_of_scope: Callable[[str], bool] | None = None
    ) -> list[str]:
        """Rendered lines for every dead waiver whose finding changed identity under it (#896).

        A fingerprinted entry whose own rule + location still carries an unwaived live
        finding: the finding re-surfaced (fail-safe on the gate), but the accepted-risk record
        is still about something present, so the advice is re-triage, never remove. This is a
        disclosure channel only: `matches()` is untouched, so no finding is suppressed that was
        not suppressed before. Empty list = no waiver lost its finding this way."""
        _, drifted, _ = self._dead_waivers(ran, out_of_scope)
        out: list[str] = []
        # A mass identity change for one check gets a single summary line ahead of the capped
        # per-entry list, the drift counterpart of `unused_waivers()`'s scan-root line.
        per_check: dict[str, int] = {}
        for k, _ in drifted:
            check = owning_check(k[1])
            per_check[check] = per_check.get(check, 0) + 1
        for check, n in sorted(per_check.items()):
            if n >= 4:
                out.append(
                    f"{n} waivers for {check} no longer match the live findings at their own rule + "
                    "location — those findings changed identity (a reworded message in this agentsec "
                    "version is the common cause); re-triage them rather than remove them"
                )
        for (fingerprint, rule, location), candidates in drifted[:_UNUSED_WAIVER_CAP]:
            if len(candidates) == 1:
                f = candidates[0]
                # A line-stripped (triage-bridged) entry carries the line-insensitive identity.
                new = f.fingerprint() if f.location == location else f.stable_fingerprint()
                live = f"the live finding at the same rule + location (fingerprint {new})"
            else:
                live = f"any of the {len(candidates)} live findings at the same rule + location"
            # Observational on purpose: "fixed at source, and a different finding now sits on
            # that line" produces exactly this shape, so the line must not assert a reword.
            out.append(
                f"waiver for {rule} @ {location} (fingerprint {fingerprint}) did not match {live} — "
                "the finding's identity changed (e.g. its message was reworded, or a different "
                "finding now sits there); re-triage rather than remove"
            )
        if len(drifted) > _UNUSED_WAIVER_CAP:
            out.append(f"…and {len(drifted) - _UNUSED_WAIVER_CAP} more waiver(s) whose finding changed identity")
        return out

    def broad_waivers(self) -> list[str]:
        """Rendered lines for every waiver that suppressed MORE THAN ONE finding.

        The disclosure channel for issue #507. The fingerprint basis
        (`findings._finding_fingerprint`) deliberately elides the line number in
        `stable_fingerprint()`, so one bridged waiver can legitimately cover several
        findings — that collapse is what makes triage tractable (csv-injection: 279
        findings, 1 verdict). What is NOT acceptable is it happening invisibly: before
        this, a waiver that suppressed 1 finding and one that suppressed 485 rendered
        identically as a single total. Empty list = every waiver covered exactly one
        finding, which is then a real signal rather than a rendering gap."""
        out: list[str] = []
        for (fingerprint, rule, location), n in sorted(self.waiver_counts.items()):
            if n < 2:
                continue
            what = rule or fingerprint or "(unnamed)"
            where = f" @ {location}" if location else ""
            out.append(
                f"waiver for {what}{where} suppressed {n} findings — confirm all {n} are "
                "the same issue (same rule + file + message head share one identity)"
            )
        return out


def load_exceptions(path: Path) -> list[Exception_]:
    if not path.is_file():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return []
    out: list[Exception_] = []
    for e in data.get("exceptions", []) if isinstance(data, dict) else []:
        # A usable exception needs a `rule` OR a `fingerprint` to match on.
        if isinstance(e, dict) and (e.get("rule") or e.get("fingerprint")):
            out.append(Exception_(
                rule=str(e.get("rule") or ""),
                location=str(e.get("location") or ""),
                reason=str(e.get("reason") or ""),
                review_by=str(e.get("review_by") or ""),
                fingerprint=str(e.get("fingerprint") or ""),
            ))
    return out


def apply_exceptions(
    findings: list[Finding], exceptions: list[Exception_], today: date
) -> ExceptionOutcome:
    outcome = ExceptionOutcome()
    # Record what was CONSIDERED, not just what fired. `apply_exceptions` is driven by
    # findings, so an entry matching nothing is never visited by the loop below and would
    # otherwise leave no trace anywhere in the outcome (issue #730).
    outcome.considered_keys = {e.key() for e in exceptions}
    seen_lapsed: set[tuple[str, str]] = set()
    seen_undated: set[tuple[str, str]] = set()
    for f in findings:
        match = next((e for e in exceptions if e.matches(f)), None)
        if match is None:
            outcome.kept.append(f)
            outcome.unwaived.append(f)
            continue
        # Every branch below is a MATCH, honored or not. Recorded once here so the three
        # outcomes can't drift apart: an entry that matched and then lapsed is live, and
        # must not fall out as "unused".
        outcome.matched_keys.add(match.key())
        if match.local and not match.review_by:
            # A project-local suppression MUST declare an expiry — no silent forever-ignores in
            # a repo's suppress.json (unlike the curated global registry's Tier-A entries). An
            # undated local entry is NOT honored: surface the finding and remind once.
            outcome.kept.append(f)
            key = (match.rule, match.location)
            if key not in seen_undated:
                seen_undated.add(key)
                loc = f" @ {match.location}" if match.location else ""
                outcome.lapsed.append(
                    f"local suppression for {match.rule}{loc} needs a `review_by` date — not honored"
                )
        elif match.lapsed(today):
            # Lapsed → re-surface the finding and remind once per exception.
            outcome.kept.append(f)
            key = (match.rule, match.location)
            if key not in seen_lapsed:
                seen_lapsed.add(key)
                loc = f" @ {match.location}" if match.location else ""
                outcome.lapsed.append(
                    f"exception for {match.rule}{loc} lapsed on {match.review_by} — renew or fix"
                )
        else:
            outcome.suppressed.append(f)
            # Attribute the suppression to the waiver that caused it, so a waiver whose
            # radius covers more than the one finding it was written about is visible
            # rather than folded into a single total (#507). Keyed like `merge_exceptions`.
            waiver_key = match.key()
            outcome.waiver_counts[waiver_key] = outcome.waiver_counts.get(waiver_key, 0) + 1
            if match.local:
                outcome.local_suppressed.append(f)
    return outcome


def load_local_exceptions(repo_root: Path) -> list[Exception_]:
    """Load project-local suppressions from <repo>/.agentsec/suppress.json.

    Same format as `agentsec-exceptions.json`. Merged with the global registry
    by `audit()` so teams can record repo-specific false positives without
    touching the tool's own registry.

    Each entry is flagged `local=True`; `apply_exceptions` then REQUIRES a
    `review_by` on it (an undated local suppression is not honored), so a repo's
    file can't become the silent forever-ignore the global Tier-A entries are
    allowed to be.
    """
    exceptions = load_exceptions(repo_root / ".agentsec" / "suppress.json")
    for e in exceptions:
        e.local = True
    return exceptions


def write_baseline(findings: list[Finding], path: Path, today: date, ttl_days: int = DEFAULT_TTL_DAYS) -> int:
    """Write all current findings as accepted exceptions (bandit-style baseline)
    so only NEW findings surface afterwards. Returns the number written."""
    review_by = date.fromordinal(today.toordinal() + ttl_days).isoformat()
    # `agentsec-exceptions.json` is a persisted, git-committed, re-read-on-every-audit artifact
    # (see module docstring) — the same machine-readable, LLM/tool-consuming JSON class as SARIF/
    # coverage/drift-snapshot, so `rule`/`location`/`reason` (built from guard/runner-authored
    # `Finding` text, which is attacker-controlled on a hostile-repo scan) must go through the
    # single `sanitize_finding()` choke point before being written (PR #581 round-3 review,
    # Critical: this call site — and `cli.py`'s `--write-baseline` handling, which only calls this
    # function — were the one persisted bypass left after round 2). `fingerprint()` stays keyed on
    # the ORIGINAL, unsanitized `f` (never `sf`) so `apply_exceptions()`'s fingerprint-matching
    # against a later re-scan is completely unaffected — same "identity survives rendering" rule
    # `drift.py`'s `_finding_to_dict` already follows.
    exceptions = []
    for f in findings:
        fingerprint = f.fingerprint()
        sf = sanitize_finding(f)
        exceptions.append({
            "rule": sf.rule or sf.check_id,
            "location": sf.location,
            "fingerprint": fingerprint,
            "reason": f"baselined {today.isoformat()} ({sf.severity}: {sf.title})",
            "review_by": review_by,
        })
    # ensure_ascii=False: keep literal unicode (—, etc.) rather than \uXXXX escapes,
    # matching the repo's other JSON writers (intake.save_ledger, checklist.json) for
    # consistent, low-noise diffs. The file is always read/written as UTF-8.
    path.write_text(
        json.dumps({"exceptions": exceptions}, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    return len(exceptions)


def merge_exceptions(
    path: Path, entries: list[dict[str, str]], today: date, ttl_days: int = DEFAULT_TTL_DAYS
) -> int:
    """Merge `entries` into the registry file at `path` (creating it if absent), de-duping on
    `(fingerprint, rule, location)` so re-running is idempotent. Any entry lacking a `review_by`
    gets a default (today + ttl_days) so a merged waiver still expires. Returns the number of NEW
    entries added; existing entries are left untouched.

    This is the triage-agnostic primitive behind the `triage → exception` bridge (issue #325):
    the caller builds entries carrying each verdict's stable fingerprint, which then match the
    finding via `Exception_.matches` (the `stable_fingerprint()` branch).

    Refuses to write (raises `ValueError`) if the existing file is present but unreadable,
    unparseable, or not a `{"exceptions": [...]}` registry — treating "can't parse" as "empty"
    would silently clobber the file (e.g. the committed baseline caught mid hand-edit). Only a
    genuinely empty/whitespace file is a safe fresh start. **Callers must catch `ValueError`** so a
    broken registry degrades gracefully rather than propagating (see `triage_cli`)."""
    if not entries:
        return 0
    review_by = date.fromordinal(today.toordinal() + ttl_days).isoformat()
    existing: list[dict[str, str]] = []
    if path.is_file():
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as err:  # UnicodeDecodeError is a ValueError, not an OSError
            raise ValueError(f"refusing to overwrite unreadable exceptions file {path}: {err}") from err
        if text.strip():
            try:
                data = json.loads(text)
            except ValueError as err:  # JSONDecodeError is a ValueError subclass
                raise ValueError(f"refusing to overwrite unparseable exceptions file {path}: {err}") from err
            if not (isinstance(data, dict) and isinstance(data.get("exceptions"), list)):
                raise ValueError(f"refusing to overwrite exceptions file {path}: unexpected top-level shape")
            existing = [e for e in data["exceptions"] if isinstance(e, dict)]

    def _key(e: dict[str, str]) -> tuple[str, str, str]:
        return (str(e.get("fingerprint") or ""), str(e.get("rule") or ""), str(e.get("location") or ""))

    seen = {_key(e) for e in existing}
    added = 0
    for e in entries:
        entry = dict(e)
        if not entry.get("review_by"):
            entry["review_by"] = review_by
        if _key(entry) in seen:
            continue
        seen.add(_key(entry))
        existing.append(entry)
        added += 1

    path.write_text(
        json.dumps({"exceptions": existing}, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    return added
