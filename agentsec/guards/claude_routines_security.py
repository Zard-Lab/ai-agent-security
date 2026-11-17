"""Guard: a Claude Code Routine (scheduled prompt) grants a wildcard permission scope wider than
the interactive default, builds its schedule expression from runtime/templated state, or grants a
sensitive permission with no audit-log declaration — a structural gap, not a named CVE: Anthropic's
own Routines feature (research preview, 2026-04-14) has no coverage anywhere in agentsec today
(checklist §4, new item; agent-audit-kit's `routines.py` AAK-ROUTINE-001..003).

Claude Code Routines run a saved prompt on a schedule, unattended, with no interactive human in
the loop to catch an over-broad permission grant or a malicious schedule the way a live session
would. Routine definitions live under `.claude/routines/*.{json,yml,yaml}`.

Three checks, all deliberately TEXT-based (not schema-parsed) — this is a research-preview
feature with no stable, fully-documented JSON/YAML schema to parse against yet, so raw-text
pattern matching is the more honest posture than assuming field names that may not survive the
feature reaching general availability:

  1. **`permission-surface-wider-than-interactive`** (MEDIUM): a wildcard permission scope
     (`fs:*`, `shell:exec` with no scoped command, `network:*`) appears in the file — broader
     than what an interactive session's own per-action confirmation would allow through.
  2. **`schedule-from-runtime-state`** (HIGH): the routine's `schedule` field's value contains a
     template/interpolation marker (`${...}`, `{{...}}`, or a bare `$VAR`) rather than a fixed
     cron-like literal — a schedule expression built from runtime state that changes what the
     routine's own next-run time is, a cron-injection shape.
  3. **`no-audit-log-declaration`** (MEDIUM): the file grants a sensitive wildcard permission
     (matching rule 1) but declares no audit-log field (`audit_log`/`auditLog`/`audit`) set to a
     truthy/enabled value anywhere in the file.

Suppress an audited case with:

    # security: allow-claude-routines-security

(also recognized as `// ...`/a JSON string literal, so it works whether the file is JSON or YAML).
"""
from __future__ import annotations

import re
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding, Severity

from .base import CanaryPlant, Guard, is_nonproduct_path, iter_files_named, pragma_present, read, rel

# A routine file is JSON or YAML, and the documented opt-out for either is a `#` comment OR the pragma as a
# string value, so a YAML comment view would void that documented form (rule 4): its pragma is matched on
# the raw text by contract (`dialect=None`, #1040 T5).
_PRAGMA = "security: allow-claude-routines-security"

_WILDCARD_PERM_RE = re.compile(
    # `shell:exec` counts only when UNSCOPED: bare, or with an explicit `:*`. A scoped form
    # (`shell:exec:git status`) names one command, so `exec` must not be followed by `:` + text.
    r"\b(?:fs|network|shell)\s*:\s*(?:\*|exec(?![\w:])|exec:\s*\*)", re.IGNORECASE,  # security: allow-eval-exec (a permission-name regex, not a call)
)
_SCHEDULE_FIELD_RE = re.compile(
    r"""\bschedule\b["']?\s*[:=]\s*["']?([^\n,"']+)""", re.IGNORECASE,
)
_TEMPLATE_INTERP_RE = re.compile(r"\$\{[^}]+\}|\{\{[^}]+\}\}|\$[A-Za-z_][A-Za-z0-9_]*\b")
_AUDIT_LOG_TRUE_RE = re.compile(
    r"""\baudit[_-]?log\b["']?\s*[:=]\s*["']?(?:true|enabled|on)\b""", re.IGNORECASE,
)

_STD_PERMISSION = ["OWASP-LLM:LLM06", "OWASP-ASI:ASI04"]
_STD_SCHEDULE = ["CWE-88"]
_STD_AUDIT = ["CWE-778"]


class ClaudeRoutinesSecurityGuard(Guard):
    id = "claude-routines-security"
    title = "Claude Code Routine grants an over-broad permission, an unstable schedule, or no audit log"
    area = "AI agent"

    # .claude/routines/nightly-report.json: permissions include "shell:exec" (unscoped) and no
    # audit_log declaration -> fires claude-routines-security/permission-surface-wider-than-interactive
    # and claude-routines-security/no-audit-log-declaration.
    canary_plant = CanaryPlant(
        files={
            ".claude/routines/nightly-report.json": (
                '{\n'
                '  "prompt": "Summarize today\'s commits and post to Slack",\n'
                '  "schedule": "0 9 * * *",\n'
                '  "permissions": ["shell:exec", "network:*"]\n'
                '}\n'
            ),
        },
        expects=frozenset({
            "claude-routines-security/permission-surface-wider-than-interactive",
            "claude-routines-security/no-audit-log-declaration",
        }),
    )

    def applies(self, profile: StackProfile) -> bool:  # noqa: ARG002
        return True

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []
        for f in iter_files_named(
            root, "*.json", "*.yml", "*.yaml", respect_gitignore=False,
        ):
            try:
                parts = f.relative_to(root).parts
            except ValueError:
                continue
            if not (".claude" in parts and "routines" in parts):
                continue
            r = rel(root, f)
            if is_nonproduct_path(r, profile.archive_segments):
                continue
            raw = read(f)
            if not raw or pragma_present(_PRAGMA, raw, dialect=None):
                continue
            out.extend(self._check(r, raw))
        return out

    def _check(self, r: str, raw: str) -> list[Finding]:
        out: list[Finding] = []

        wildcard_match = _WILDCARD_PERM_RE.search(raw)
        if wildcard_match:
            out.append(self._finding(
                r, "permission-surface-wider-than-interactive", "medium", _STD_PERMISSION,
                f"This routine grants a wildcard permission scope ({wildcard_match.group(0)!r}) "
                "wider than what an interactive session's own per-action confirmation would "
                "allow through. A routine runs unattended on a schedule, with no human in the "
                "loop to catch an over-broad grant the way a live session would.",
                "Scope the permission to the specific paths/commands/hosts the routine "
                "actually needs, rather than a wildcard.",
            ))

        schedule_match = _SCHEDULE_FIELD_RE.search(raw)
        if schedule_match and _TEMPLATE_INTERP_RE.search(schedule_match.group(1)):
            out.append(self._finding(
                r, "schedule-from-runtime-state", "high", _STD_SCHEDULE,
                f"The schedule field ({schedule_match.group(0).strip()!r}) is built from a "
                "template/interpolated value rather than a fixed cron-like literal. Runtime "
                "state that influences when (or how often) a routine runs is a cron-injection "
                "shape — a value an attacker can influence changes the routine's own "
                "execution schedule.",
                "Use a fixed, literal schedule expression. If the schedule genuinely must "
                "vary, validate the resolved value against a strict allow-listed pattern "
                "before it is used, not after.",
            ))

        if wildcard_match and not _AUDIT_LOG_TRUE_RE.search(raw):
            out.append(self._finding(
                r, "no-audit-log-declaration", "medium", _STD_AUDIT,
                "This routine grants a sensitive wildcard permission but declares no "
                "audit-log field. An unattended, scheduled action with broad permissions and "
                "no audit trail is invisible if it does something unexpected.",
                "Enable audit logging for this routine (an `audit_log`/`auditLog` field set "
                "to true/enabled), especially given the wildcard permission scope it holds.",
            ))

        return out

    def _finding(
        self, r: str, rule_suffix: str, severity: Severity, standards: list[str],
        message: str, remediation: str,
    ) -> Finding:
        return Finding(
            check_id=self.id,
            severity=severity,
            title=self.title,
            location=r,
            message=message,
            remediation=remediation,
            rule=f"claude-routines-security/{rule_suffix}",
            standards=list(standards),
        )
