"""Snapshot-based drift detection — compare security posture over time.

agentsec drift <repo>           compare current findings against saved snapshot
agentsec drift <repo> --save    run audit and save current snapshot
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

from agentsec.findings import Finding, history_note, is_historical, sanitize_finding, strip_line_suffix
from agentsec.text_sanitize import neutralize_delivery_markers

DEFAULT_SNAPSHOT = ".agentsec/snapshot.json"
SNAPSHOT_VERSION = 2

# Why a snapshot did or did not load. Only "ok" is a baseline, and "ok" with zero entries is a CLEAN
# baseline, not a missing one: the entry count cannot carry this, because a saved `[]` and an absent
# file both read as `[]` (#854).
SnapshotStatus = Literal["ok", "absent", "unreadable", "unsupported-version"]


@dataclass(frozen=True)
class LoadedSnapshot:
    status: SnapshotStatus
    entries: list[dict[str, Any]] = field(default_factory=list)
    detail: str = ""          # why a non-"ok" file could not be used, for the report


@dataclass
class DriftResult:
    new: list[Finding]        # regressions: in current, not in snapshot
    resolved: list[dict[str, Any]]  # improvements: in snapshot, not in current
    unchanged_count: int      # stable count
    snapshot_status: SnapshotStatus
    snapshot_detail: str = ""
    # #853: findings in BOTH sets whose gate verdict (`findings.is_historical`) flipped. The verdict
    # is kept out of `fingerprint()` so waivers and SARIF alert identities survive a dump being added
    # or removed, which made a pure fingerprint diff count these as "unchanged". Only a snapshot row
    # that recorded the verdict (`"historical"`, saved since #853) can produce either list.
    reactivated: list[Finding] = field(default_factory=list)  # superseded history then, live now
    demoted: list[Finding] = field(default_factory=list)      # live then, superseded history now
    # Rows that can never show either flip: saved before #853 for a finding a dump could supersede
    # (`legacy_schema_rows`). Disclosed in the report so an old snapshot cannot read as a full check.
    legacy_schema_rows: int = 0

    @property
    def snapshot_existed(self) -> bool:
        """A usable baseline was loaded, including an empty one. A file that is present but corrupt or
        from another snapshot version is not a baseline, so it reads False here too."""
        return self.snapshot_status == "ok"

    @property
    def gating_new(self) -> list[Finding]:
        """The regressions the exit code counts: `new` minus superseded (historical) SQL findings.
        `drift` gates by fingerprint, not severity, so it cannot share `cli._gating()`, but it applies
        the same exclusion (`findings.is_historical`) — before this, a policy added to a migration on a
        repo that ships a dump was stamped superseded, exited 0 under `audit`, and still failed `drift`
        as a "regression" (#829 review of #800). Still listed in the report, tagged, non-gating."""
        return [f for f in self.new if not is_historical(f)]

    @property
    def gating(self) -> list[Finding]:
        """Every finding the `drift` exit code counts: the live regressions plus the reactivated
        findings. A reactivated finding is the same regression `audit` fails on (the dump that made
        it history went away), so it gates even though its fingerprint did not change. `demoted` never
        gates: adopting a dump is a legitimate quiet pass, disclosed in the report instead."""
        return self.gating_new + self.reactivated


def _finding_to_dict(f: Finding) -> dict[str, Any]:
    # `title`/`message`/`location` neutralized via `sanitize_finding()`: this snapshot is the
    # same machine-readable, LLM/tool-consuming JSON class as SARIF/coverage JSON (`agentsec
    # drift` reads it back and reports on it), so it carries the same structural
    # prompt-injection-marker risk from guard/runner-authored text — see `text_sanitize.py`'s
    # module docstring. `location` in particular is attacker-controlled via a hostile filename
    # and was missed here entirely before (round-2 review of PR #581). `fingerprint()` stays
    # keyed on the ORIGINAL `f`, not the sanitized copy, so drift identity is unaffected.
    # `historical` records the gate VERDICT, not the raw `superseded` stamp (a `confirmed-live`
    # provenance overrides the stamp), because the verdict is what both readers compare: the
    # drift diff and the `--baseline-snapshot` ratchet (#853). Additive, so SNAPSHOT_VERSION stays:
    # a bump would load every committed baseline as empty and fail every ratchet on upgrade.
    fingerprint = f.fingerprint()
    sf = sanitize_finding(f)
    return {
        "fingerprint": fingerprint,
        "check_id": sf.check_id,
        "rule": sf.rule or sf.check_id,
        "severity": sf.severity,
        "location": sf.location,
        "title": sf.title,
        "message": sf.message,
        "historical": is_historical(f),
    }


def save_snapshot(findings: list[Finding], path: Path) -> int:
    """Save current findings as a drift baseline. Returns count saved."""
    path.parent.mkdir(parents=True, exist_ok=True)
    data: dict[str, Any] = {
        "version": SNAPSHOT_VERSION,
        "findings": [_finding_to_dict(f) for f in findings],
    }
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return len(findings)


def read_snapshot(path: Path) -> LoadedSnapshot:
    """Load a saved snapshot and say whether it is a usable baseline (`status == "ok"`) or why not."""
    if not path.is_file():
        return LoadedSnapshot("absent")
    # A non-UTF-8 file raises UnicodeDecodeError, deliberately NOT caught below: mapping it to
    # "unreadable" would make `load_snapshot` return [] to callers that render [] as a clean run
    # (#1036). The crash fails closed; change the two together.
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        return LoadedSnapshot("unreadable", detail=f"not valid JSON ({e.msg} at line {e.lineno}, column {e.colno})")
    except OSError as e:
        return LoadedSnapshot("unreadable", detail=f"could not be read ({e.strerror or type(e).__name__})")
    if not isinstance(data, dict):
        return LoadedSnapshot("unreadable", detail="the top level is not a JSON object")
    version = data.get("version")
    if version != SNAPSHOT_VERSION:
        # Echo the version only when it is a plain integer: the file can be repo-controlled and this
        # text lands in the report, so an arbitrary string is never copied through.
        shown = (f"snapshot version {version}" if type(version) is int
                 else "no snapshot version" if version is None else "a non-integer snapshot version")
        return LoadedSnapshot(
            "unsupported-version", detail=f"{shown}; this agentsec reads version {SNAPSHOT_VERSION}"
        )
    raw = data.get("findings")
    if not isinstance(raw, list):
        return LoadedSnapshot("unreadable", detail="`findings` is not a list")
    return LoadedSnapshot("ok", [r for r in raw if isinstance(r, dict) and r.get("fingerprint")])


def legacy_schema_rows(snapshot: list[dict[str, Any]]) -> int:
    """How many rows cannot show the superseded -> live flip: rows without a boolean `historical`
    (saved before #853) for a finding a dump could have superseded, that is a schema-state check
    anchored in a `.sql` file (`sql_state.is_superseded`'s own test). A re-saved snapshot, or an old
    one with no such row, counts 0, so the disclosure stays quiet wherever the flip cannot happen
    (#1038 round 1). Shared by the drift report, the `--baseline-snapshot` ratchet and `ci doctor`."""
    from agentsec.sql_state import is_schema_state_check  # lazy: it imports the registry

    return sum(
        1 for r in snapshot
        if not isinstance(r.get("historical"), bool)
        and strip_line_suffix(str(r.get("location", ""))).replace("\\", "/").endswith(".sql")
        and is_schema_state_check(str(r.get("check_id", "")))
    )


def load_snapshot(path: Path) -> list[dict[str, Any]]:
    """Load saved snapshot entries. Returns [] when absent or malformed."""
    return read_snapshot(path).entries


def diff_snapshot(current: list[Finding], snapshot: LoadedSnapshot) -> DriftResult:
    """Diff current findings vs snapshot by fingerprint, then compare the gate verdict across the
    findings both sides share (#853). The snapshot's status is passed through, never inferred from
    its entry count (#854). A row without a boolean `historical` (saved before #853, or malformed)
    yields no transition either way: the pre-#853 behaviour, and the side that can never invent a
    regression. Such a snapshot gains the check once it is re-saved."""
    snap_fps: dict[str, dict[str, Any]] = {}
    for r in snapshot.entries:
        # Duplicate rows for one fingerprint (a hand-merged snapshot): a row that is not
        # `historical: true` wins, so a fingerprint was history only when every row says so. That
        # is the rule the ratchet's `cli._baseline_gate_exclude` applies, so the two cannot disagree.
        held = snap_fps.get(r["fingerprint"])
        if held is None or held.get("historical") is True:
            snap_fps[r["fingerprint"]] = r
    cur_fps = {f.fingerprint(): f for f in current}

    new = [f for fp, f in cur_fps.items() if fp not in snap_fps]
    resolved = [r for fp, r in snap_fps.items() if fp not in cur_fps]
    reactivated: list[Finding] = []
    demoted: list[Finding] = []
    unchanged_count = 0
    for fp, f in cur_fps.items():
        row = snap_fps.get(fp)
        if row is None:
            continue
        was, now = row.get("historical"), is_historical(f)
        if was is True and not now:
            reactivated.append(f)
        elif was is False and now:
            demoted.append(f)
        else:
            unchanged_count += 1

    return DriftResult(
        new=new,
        resolved=resolved,
        unchanged_count=unchanged_count,
        snapshot_status=snapshot.status,
        snapshot_detail=snapshot.detail,
        reactivated=reactivated,
        demoted=demoted,
        legacy_schema_rows=legacy_schema_rows(snapshot.entries),
    )


def _finding_line(x: Finding, tag: str = "") -> str:
    """One report bullet for a CURRENT-scan finding, neutralized through `sanitize_finding`."""
    f = sanitize_finding(x)
    return f"- **[{f.severity.upper()}]** `{f.rule or f.check_id}` @ `{f.location}` — {f.title}{tag}"


def to_markdown(result: DriftResult, snapshot_path: Path) -> str:
    lines = [f"# agentsec drift report\n\nBaseline: `{snapshot_path}`\n"]

    if result.snapshot_status == "absent":
        lines.append(
            "_No snapshot found. Run `agentsec drift <repo> --save` to create one, "
            "then re-run to track changes._\n"
        )
        return "\n".join(lines)

    if result.snapshot_status != "ok":
        # The file is present but unusable (corrupt, or another snapshot version). Never advise a
        # bare `--save` here: re-saving would accept every current finding, regressions included, as
        # the new baseline. Fail closed (every finding counts as new) and say so (#854).
        lines.append(
            f"_The baseline file exists but could not be used: {result.snapshot_detail}. "
            "Every current finding is treated as new, so this run fails closed._\n"
        )
        # Restoring an old-version file from version control only returns the same old file.
        first = ("Restore the file from version control." if result.snapshot_status == "unreadable"
                 else "Compare with the agentsec version that wrote it.")
        lines.append(
            f"_{first} Re-saving it would accept every current finding "
            "into the baseline, so re-baseline only after reviewing `agentsec audit <repo>`._\n"
        )
        return "\n".join(lines)

    # Every baseline fingerprint lands in exactly one of these four, so all four empty is an empty
    # baseline. `unchanged_count` alone is not enough: a row whose verdict flipped (#853) counts in
    # `reactivated`/`demoted` instead, and must not read as "0 findings".
    if not (result.resolved or result.unchanged_count or result.reactivated or result.demoted):
        lines.append("_The baseline holds 0 findings (a clean baseline)._\n")

    n_hist = len(result.new) - len(result.gating_new)
    hist_note = f" (of which {n_hist} governed by the schema dump — non-gating)" if n_hist else ""
    flips = ""
    if result.reactivated:
        flips += f"  ·  **{len(result.reactivated)} reactivated** (superseded → live)"
    if result.demoted:
        flips += f"  ·  **{len(result.demoted)} demoted** (live → superseded, non-gating)"
    lines.append(
        f"**{len(result.new)} new** (regressions){hist_note}  ·  "
        f"**{len(result.resolved)} resolved** (improvements)  ·  "
        f"**{result.unchanged_count} unchanged**{flips}\n"
    )
    if result.legacy_schema_rows:
        lines.append(
            f"_{result.legacy_schema_rows} snapshot row(s) for SQL findings predate the superseded "
            "verdict, so a superseded finding that comes back live cannot be detected for them. "
            "Re-save the snapshot (`agentsec drift --save`) with the schema dump in place, if the "
            "repo ships one._\n"
        )

    if result.new:
        lines.append("## New findings (regressions)\n")
        for x in sorted(result.new, key=lambda x: (x.severity, x.location)):
            tag = f"  _({history_note(sanitize_finding(x))} — non-gating)_" if is_historical(x) else ""
            lines.append(_finding_line(x, tag))
        lines.append("")

    if result.reactivated:
        lines.append("## Reactivated findings (superseded → live)\n")
        lines.append(
            "_Recorded as superseded history in the snapshot, live and gating now. The schema dump "
            "that governed their file may have been removed, renamed or moved out of the scanned tree, "
            "or may no longer read as a pg_dump._\n"
        )
        for x in sorted(result.reactivated, key=lambda x: (x.severity, x.location)):
            lines.append(_finding_line(x))
        lines.append("")

    if result.demoted:
        lines.append("## Demoted findings (live → superseded, non-gating)\n")
        lines.append(
            "_Live in the snapshot, superseded history now: the schema dump named on each line governs "
            "their file, so they no longer gate. Confirm it is the authoritative dump._\n"
        )
        for x in sorted(result.demoted, key=lambda x: (x.severity, x.location)):
            lines.append(_finding_line(x, f"  _({history_note(sanitize_finding(x))})_"))
        lines.append("")

    if result.resolved:
        lines.append("## Resolved findings (improvements)\n")
        for r in sorted(result.resolved, key=lambda x: x.get("location", "")):
            # `r["title"]`/`r["location"]` were already neutralized by `_finding_to_dict` at save
            # time - re-applying here is idempotent and also covers a snapshot written before this
            # fix existed (location wasn't neutralized at save time until round-2 of PR #581).
            lines.append(
                f"- ~~`{r.get('rule', '')}`~~ "
                f"@ `{neutralize_delivery_markers(r.get('location', ''))}` "
                f"— {neutralize_delivery_markers(r.get('title', ''))}"
            )
        lines.append("")

    if not (result.new or result.resolved or result.reactivated or result.demoted):
        lines.append("_No drift — security posture is unchanged since the last snapshot._\n")

    return "\n".join(lines)
