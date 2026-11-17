"""Report generation — reads triage + scan output, produces structured Markdown.

Mirrors coverage.py: compute-once result dataclass → to_markdown emitter.
Pure stdlib string construction; no templating engine.

Sections (all generated from data):
  1. Summary table — TP/FP/pending counts, FP rate, fix_status breakdown
  2. Per-check breakdown — one row per guard that fired
  3. Scan delta — before/after per guard (--compare / --from-snapshot only)
  4. Fixed findings with risk narrative
  5. Open real issues (open + deferred)
  6. Guard improvement catalog — FP reasons grouped by guard
  7. Pre-launch & ops checklist — manual items applicable to this stack
"""

from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from agentsec.findings import sanitize_finding

if TYPE_CHECKING:
    from agentsec.checklist import ChecklistItem
    from agentsec.findings import Finding
    from agentsec.triage import AnnotatedFinding

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]


@dataclass
class ReportResult:
    annotated: list[AnnotatedFinding]
    baseline_findings: list[Finding] | None
    run_date: str
    manual_items: list[ChecklistItem] = field(default_factory=list)

    def to_markdown(self) -> str:
        sections: list[str] = [f"# Security Report — {self.run_date}", ""]
        sections.append(_summary_table(self.annotated))
        sections.append(_per_check_table(self.annotated))
        if self.baseline_findings is not None:
            current = [a.finding for a in self.annotated]
            sections.append(_delta_table(current, self.baseline_findings))
        sections.append(_fixed_risks(self.annotated))
        sections.append(_open_issues(self.annotated))
        sections.append(_guard_improvements(self.annotated))
        if self.manual_items:
            sections.append(_manual_checklist(self.manual_items))
        return "\n".join(s for s in sections if s)


def build_report(
    annotated: list[AnnotatedFinding],
    baseline_findings: list[Finding] | None,
    run_date: str,
    manual_items: list[ChecklistItem] | None = None,
) -> ReportResult:
    return ReportResult(
        annotated=annotated,
        baseline_findings=baseline_findings,
        run_date=run_date,
        manual_items=manual_items or [],
    )


def _summary_table(annotated: list[AnnotatedFinding]) -> str:
    total = len(annotated)
    real = sum(1 for a in annotated if a.verdict and a.verdict.verdict == "real")
    fp = sum(
        1 for a in annotated
        if a.verdict and a.verdict.verdict in ("fp", "guard-improvement")
    )
    pending = sum(1 for a in annotated if not a.verdict or a.verdict.verdict == "pending")
    fp_rate = f"{fp / total:.0%}" if total else "n/a"
    fixed = sum(
        1 for a in annotated
        if a.verdict and a.verdict.verdict == "real" and a.verdict.fix_status == "fixed"
    )
    open_count = sum(
        1 for a in annotated
        if a.verdict and a.verdict.verdict == "real" and a.verdict.fix_status in ("open", "")
    )
    deferred = sum(
        1 for a in annotated
        if a.verdict and a.verdict.verdict == "real" and a.verdict.fix_status == "deferred"
    )

    lines = [
        "## Summary",
        "",
        "| Metric | Value |",
        "|---|---|",
        f"| Total findings | {total} |",
        f"| Real (TP) | {real} |",
        f"| False positive | {fp} |",
        f"| Pending triage | {pending} |",
        f"| FP rate | {fp_rate} |",
        f"| Fixed | {fixed} |",
        f"| Open | {open_count} |",
        f"| Deferred | {deferred} |",
        "",
    ]
    return "\n".join(lines)


def _per_check_table(annotated: list[AnnotatedFinding]) -> str:
    by_guard: dict[str, list[AnnotatedFinding]] = defaultdict(list)
    for a in annotated:
        by_guard[a.finding.check_id].append(a)

    rows = [
        "## Per-Check Breakdown",
        "",
        "| Guard | Total | Real | FP | Improvement noted |",
        "|---|---|---|---|---|",
    ]
    for guard_id in sorted(by_guard):
        items = by_guard[guard_id]
        total = len(items)
        real = sum(1 for a in items if a.verdict and a.verdict.verdict == "real")
        fp = sum(
            1 for a in items
            if a.verdict and a.verdict.verdict in ("fp", "guard-improvement")
        )
        has_improvement = any(
            a.verdict and a.verdict.improvement
            for a in items
        )
        rows.append(
            f"| {guard_id} | {total} | {real} | {fp} | {'yes' if has_improvement else ''} |"
        )
    rows.append("")
    return "\n".join(rows)


def _delta_table(
    current: list[Finding],
    baseline: list[Finding],
) -> str:
    by_guard_current: dict[str, int] = defaultdict(int)
    by_guard_baseline: dict[str, int] = defaultdict(int)
    for f in current:
        by_guard_current[f.check_id] += 1
    for f in baseline:
        by_guard_baseline[f.check_id] += 1

    all_guards = sorted(set(by_guard_current) | set(by_guard_baseline))
    rows = [
        "## Scan Delta",
        "",
        "| Guard | Before | After | Delta | Status |",
        "|---|---|---|---|---|",
    ]
    for guard_id in all_guards:
        before = by_guard_baseline[guard_id]
        after = by_guard_current[guard_id]
        delta = after - before
        delta_str = f"+{delta}" if delta > 0 else str(delta)
        status = "eliminated" if after == 0 and before > 0 else ("new" if before == 0 else "")
        rows.append(f"| {guard_id} | {before} | {after} | {delta_str} | {status} |")
    rows.append("")
    return "\n".join(rows)


def _fixed_risks(annotated: list[AnnotatedFinding]) -> str:
    fixed = [
        a for a in annotated
        if a.verdict
        and a.verdict.verdict == "real"
        and a.verdict.fix_status == "fixed"
    ]
    if not fixed:
        return ""
    lines = ["## Fixed Findings — What Cannot Happen Now", ""]
    for a in fixed:
        # `sanitize_finding()` is the choke point for a Finding's LLM/tool-facing text - this
        # report is exactly the channel PR #581's round-2 review found completely unwired
        # (Critical: `report.py` didn't import the sanitizer at all).
        f = sanitize_finding(a.finding)
        risk = a.verdict.risk if a.verdict and a.verdict.risk else (
            f"{f.title} — {f.remediation or f.message}"
        )
        commit_note = f" (commit {a.verdict.fix_commit})" if a.verdict and a.verdict.fix_commit else ""
        lines.append(f"**{f.check_id}** `{f.location}`{commit_note}")
        lines.append(f"> {risk}")
        lines.append("")
    return "\n".join(lines)


def _open_issues(annotated: list[AnnotatedFinding]) -> str:
    open_items = [
        a for a in annotated
        if a.verdict
        and a.verdict.verdict == "real"
        and a.verdict.fix_status in ("open", "deferred", "")
    ]
    if not open_items:
        return ""
    lines = ["## Open Real Issues", ""]
    for a in open_items:
        f = sanitize_finding(a.finding)
        status = a.verdict.fix_status if a.verdict and a.verdict.fix_status else "open"
        risk = a.verdict.risk if a.verdict and a.verdict.risk else (
            f.remediation or f.message
        )
        lines.append(
            f"- **[{status}]** `{f.check_id}` {f.location} — {risk}"
        )
    lines.append("")
    return "\n".join(lines)


def _section_key(section: str) -> tuple[int, str]:
    """Natural sort key so e.g. §2a sorts before §10 (not lexicographically after)."""
    m = re.match(r"(\d+)([a-z]*)", section)
    return (int(m.group(1)), m.group(2)) if m else (999, section)


def _manual_checklist(items: list[ChecklistItem]) -> str:
    """Pre-launch and ops checklist — manual items that require human confirmation.

    Each item is tagged from its per-item ``surface`` (checklist.json): ``code`` =
    reviewable from repository files (source, config, lockfile, tests) → actionable with
    ``/security-audit``; ``ops`` = needs the live/deploy environment or a process check.
    Section is deliberately NOT used to derive the tag — several sections mix both kinds.
    """
    by_sev: dict[str, list[ChecklistItem]] = {s: [] for s in SEVERITY_ORDER}
    for item in items:
        sev = item.severity if item.severity in by_sev else "info"
        by_sev[sev].append(item)

    total = len(items)
    n_code = sum(1 for it in items if it.surface == "code")
    lines = [
        "## Pre-launch & Ops Checklist (Manual)",
        "",
        f"The {total} item(s) below require manual confirmation — static analysis cannot verify them.",
        f"`[code-checkable]` ({n_code}) can be reviewed with `/security-audit` (reads your source); "
        f"`[ops]` ({total - n_code}) need a live server, deployment environment, or process check.",
        "",
    ]

    sev_labels = {
        "critical": "### Critical — must verify before launch",
        "high": "### High — required for production",
        "medium": "### Medium — strongly recommended",
        "low": "### Low — best practice",
        "info": "### Informational",
    }

    for sev in SEVERITY_ORDER:
        sev_items = by_sev[sev]
        if not sev_items:
            continue
        lines.append(sev_labels[sev])
        lines.append("")
        for item in sorted(sev_items, key=lambda x: _section_key(x.section)):
            tag = "code-checkable" if item.surface == "code" else "ops"
            std_note = f" _{', '.join(item.standards)}_" if item.standards else ""
            lines.append(f"- [ ] **`{item.id}`** [{tag}] — {item.title}{std_note}")
        lines.append("")

    return "\n".join(lines)


def _guard_improvements(annotated: list[AnnotatedFinding]) -> str:
    improvements = [
        a for a in annotated
        if a.verdict
        and a.verdict.verdict in ("fp", "guard-improvement")
        and a.verdict.improvement
    ]
    if not improvements:
        return ""
    by_guard: dict[str, list[AnnotatedFinding]] = defaultdict(list)
    for a in improvements:
        by_guard[a.finding.check_id].append(a)

    rows = [
        "## Guard Improvement Catalog",
        "",
        f"{len(improvements)} specific improvements identified.",
        "",
        "| Guard | FP Pattern | Recommended Fix |",
        "|---|---|---|",
    ]
    for guard_id in sorted(by_guard):
        for a in by_guard[guard_id]:
            if a.verdict is None:  # never — guaranteed by the filter above; narrows for type-checkers
                continue
            reason = (a.verdict.reason or "—").replace("|", "\\|")
            improvement = (a.verdict.improvement or "—").replace("|", "\\|")
            rows.append(f"| {guard_id} | {reason} | {improvement} |")
    rows.append("")
    return "\n".join(rows)
