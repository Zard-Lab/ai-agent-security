"""Guard: a coding-agent CLI is run headlessly in CI, or checked-in agent settings /
instruction files persist trust across every invocation (checklist §4, new item;
agent-audit-kit's `agent_trust_surface.py` AAK-AGENT-TRUST-001..004).

Coding agents auto-load repo-resident config and skill files on open and trust them on
first use — the interactive workspace-trust prompt is the one guardrail in that path. A
risk assessment of malicious skill files (arXiv:2608.05223, 2026-08-05) measured Gemini CLI
executing shell commands hidden in benign-appearing skill files in 95.5-96.1% of runs and
Qwen Code in 71.6-74.0%, with explicit safety recognition in only 1.99% of 5,629 runs (a
three-judge panel validated against a blind human gold standard, Cohen's kappa 0.85). A
non-interactive `-p`/headless CI run is exactly what removes that one guardrail.

Four checks:

  1. **`headless-agent-cli-in-ci`** (MEDIUM, surfacing): a CI workflow runs a coding-agent CLI
     non-interactively (`claude -p`/`--dangerously-skip-permissions`, `gemini --yolo`,
     `codex exec`/`--full-auto`, `aider --yes`, a first-party agent GitHub Action, ...).
  2. **`headless-agent-on-untrusted-trigger`** (CRITICAL): the same shape on a workflow
     trigger where checked-out content can be attacker-controlled
     (`pull_request_target`/`issue_comment`/`workflow_run`/an explicit PR-head checkout) —
     a fork PR's skill/config files execute with the base repo's secrets, no trust prompt.
  3. **`settings-persist-trust`** (HIGH): a checked-in agent settings file
     (`.claude/settings.json`, `.gemini/settings.json`, `.cursor/settings.json`,
     `.codex/config.toml`, `.opencode/config.json`, ...) bakes in trust/auto-approval
     (`bypassPermissions`, `autoApprove`, `yolo`, `trust: true`) — first-use trust survives
     every subsequent invocation and travels with a fork.
  4. **`gemini-instruction-shell-payload`** (CRITICAL): a `GEMINI.md`/`.gemini/*.md`
     context file (auto-loaded on session start) carries an embedded shell payload
     (a fenced shell block, or a `curl|wget` piped to a shell).

Suppress an audited case with:

    # security: allow-agent-headless-trust-surface
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Literal

from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import (
    CanaryPlant,
    Guard,
    comment_dialect_for,
    is_nonproduct_path,
    iter_files,
    iter_files_named,
    pragma_present,
    read,
    rel,
    strip_hash_comments,
)

_PRAGMA = re.compile(r"#\s*security:\s*allow-agent-headless-trust-surface")

_HEADLESS_AGENT_RES: tuple[re.Pattern[str], ...] = (
    re.compile(r"\bclaude\b[^\n|&;]*?(?:\s-p\b|--print\b|--dangerously-skip-permissions\b|--permission-mode[= ]+bypassPermissions)", re.I),
    re.compile(r"\banthropics/claude-code(?:-base)?-action\b", re.I),
    re.compile(r"\bgemini\b[^\n|&;]*?(?:\s-p\b|--yolo\b|--approval-mode[= ]+yolo|-y\b)", re.I),
    re.compile(r"\b(?:google-github-actions/run-gemini-cli|google-gemini/[\w.-]*gemini[\w.-]*action)\b", re.I),
    re.compile(r"\bqwen\b[^\n|&;]*?\s-p\b", re.I),
    re.compile(r"\bcursor-agent\b", re.I),
    re.compile(r"\baider\b[^\n|&;]*?(?:--yes\b|--yolo\b)", re.I),
    re.compile(r"\bcodex\b[^\n|&;]*?(?:\bexec\b|--full-auto\b|--dangerously-bypass-approvals(?:-and-sandbox)?\b)", re.I),
    re.compile(r"\bopenai/codex-action\b", re.I),
    re.compile(r"\bopencode\b[^\n|&;]*?\brun\b", re.I),
    re.compile(r"--dangerously-skip-permissions\b|--dangerously-bypass-approvals(?:-and-sandbox)?\b", re.I),
)
_UNTRUSTED_TRIGGER_RE = re.compile(
    r"^[^\S\n]*(?:-\s*)?(pull_request_target|issue_comment|workflow_run|pull_request_review_comment|pull_request_review)\b",
    re.M,
)
_PR_HEAD_REF_RE = re.compile(
    r"github\.event\.pull_request\.head\b|github\.head_ref\b", re.I,
)
_CHECKOUT_USES_RE = re.compile(r"\buses:\s*['\"]?actions/checkout\b", re.I)
_CHECKOUT_WITH_RE = re.compile(r"^\s*(?:ref|repository):\s*(?P<v>.*)$", re.I)


def _pr_head_checkout(text: str) -> str | None:
    """Return the offending `ref:`/`repository:` value when an `actions/checkout` step checks out
    the PR head (fork code), else None. A head reference anywhere else (an `if:` fork gate, an
    `echo`) does not check anything out, so it is not counted."""
    lines = text.splitlines()
    for i, line in enumerate(lines):
        if not _CHECKOUT_USES_RE.search(line):
            continue
        # Step bounds: back to the `- ` that opens the step, forward to the next sibling `- `.
        start = i
        while start > 0 and not re.match(r"^\s*-\s", lines[start]):
            start -= 1
        dash_indent = len(lines[start]) - len(lines[start].lstrip())
        end = i + 1
        while end < len(lines):
            ln = lines[end]
            if ln.strip() and len(ln) - len(ln.lstrip()) <= dash_indent:
                break
            end += 1
        for ln in lines[start:end]:
            m = _CHECKOUT_WITH_RE.match(ln)
            if m and _PR_HEAD_REF_RE.search(m.group("v")):
                return m.group("v").strip()
        # The line-anchored form above misses a `with:` written as a YAML FLOW mapping on one
        # line (`with: {ref: ${{ github.event.pull_request.head.sha }}}`), which is ordinary,
        # valid YAML and not merely a stylistic edge case. Fall back to a whole-step-block search
        # for the same reference; still scoped to this checkout step's own bounds, so an `if:`
        # fork gate or an `echo` elsewhere in the workflow still does not count (round-1's fix).
        block = "\n".join(lines[start:end])
        m2 = _PR_HEAD_REF_RE.search(block)
        if m2:
            return block[max(0, m2.start() - 20):m2.end() + 20].strip()
    return None


_SETTINGS_FILES: tuple[str, ...] = (
    ".claude/settings.json", ".claude/settings.local.json", ".gemini/settings.json",
    ".cursor/settings.json", ".cursor/environment.json", ".codex/config.toml", ".opencode/config.json",
)
_TRUST_FLAG_RE = re.compile(
    r'"?(?:bypassPermissions|dangerouslySkipPermissions)"?'
    r'|"permissionMode"\s*:\s*"bypassPermissions"'
    r'|"defaultMode"\s*:\s*"bypassPermissions"'
    r'|"?(?:autoApprove|auto_approve|autoExecute|auto_execute)"?\s*:\s*(?:true|\[)'
    r'|"?(?:yolo|full_auto|fullAuto)"?\s*:\s*true'
    r'|"?trust"?\s*:\s*true'
    r'|approval[_-]?mode\s*[:=]\s*"?(?:yolo|never|full-auto)"?',
    re.I,
)
_SHELL_PAYLOAD_RE = re.compile(
    r"```(?:ba|z)?sh(?:ell)?\b|`{3}console\b|\bcurl\b[^\n]*\|\s*(?:ba|z)?sh\b"
    r"|\bwget\b[^\n]*\|\s*(?:ba)?sh\b|\beval\s*\(",
    re.I,
)

_STD_TRIGGER = ["OWASP-ASI:ASI04", "CWE-829"]
_STD_SETTINGS = ["OWASP-ASI:ASI04", "CWE-269"]


class AgentHeadlessTrustSurfaceGuard(Guard):
    id = "agent-headless-trust-surface"
    title = "Coding agent run headlessly in CI, or trust persisted via checked-in settings/instructions"
    area = "AI agent"
    # headless-agent-cli-in-ci flags an architecture to confirm (the upstream claude-code-action
    # workflow trips it on every adopting repo), not a proven bug: MEDIUM + review-tier so adopting
    # the release does not fail a default `--fail-on high` gate. The untrusted-trigger CRITICAL
    # and settings-persist-trust HIGH stay proven, gating findings.
    surfacing_rule_prefixes = ("agent-headless-trust-surface/headless-agent-cli-in-ci",)

    # .github/workflows/agent.yml: claude -p run on pull_request_target, with an explicit
    # checkout of the PR head ref (the actual attacker-controlled-content shape) -> fires
    # agent-headless-trust-surface/headless-agent-on-untrusted-trigger.
    canary_plant = CanaryPlant(
        files={
            ".github/workflows/agent.yml": (
                "on:\n  pull_request_target:\n"
                "jobs:\n  run:\n    runs-on: ubuntu-latest\n    steps:\n"
                "      - uses: actions/checkout@v4\n"
                "        with:\n"
                "          ref: ${{ github.event.pull_request.head.sha }}\n"
                "      - run: claude -p \"review this PR\"\n"
            ),
        },
        expects=frozenset({
            "agent-headless-trust-surface/headless-agent-on-untrusted-trigger",
        }),
    )

    def applies(self, profile: StackProfile) -> bool:  # noqa: ARG002
        return True

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []

        wf_dir = root / ".github" / "workflows"
        if wf_dir.is_dir():
            for wf in sorted(wf_dir.iterdir()):
                if not (wf.is_file() and wf.suffix in (".yml", ".yaml")):
                    continue
                r = rel(root, wf)
                if is_nonproduct_path(r, profile.archive_segments):
                    continue
                text = read(wf)
                # `hash`, not `yaml` (#1000 D1): the headless-agent call lives in a `run: |` script,
                # so a `#` shell comment beside it is the natural opt-out, and the `yaml` view reads
                # a block scalar as content. A quoted scalar is still not a comment under `hash`.
                if not text or pragma_present(_PRAGMA, text, dialect="hash"):
                    continue
                # (root-caused against the real anthropics/claude-code-action repo): a
                # commented-out job (a disabled `repository: anthropics/claude-code-base-action`
                # checkout under a `#`-prefixed block) still hit _HEADLESS_AGENT_RES, since YAML
                # comments were never stripped before scanning -- the same class strip_hash_comments
                # exists for elsewhere in this codebase.
                scan_text = strip_hash_comments(text)
                hit = next((m for rx in _HEADLESS_AGENT_RES if (m := rx.search(scan_text))), None)
                if hit is None:
                    continue
                # continued: an untrusted TRIGGER alone used to be sufficient for
                # CRITICAL via `or`, with no correlation to whether the workflow actually checks
                # out attacker-controlled content. That flagged claude-code-action's own reference
                # workflows -- issue_comment/pull_request_review(_comment) triggers with a plain
                # `actions/checkout@v6` (no `ref:` override, so it checks out the safe base ref),
                # and a `pull_request` trigger (not in the untrusted-trigger list) whose `if:` gate
                # explicitly checks `github.event.pull_request.head.repo.full_name ==
                # github.repository` -- a SAFETY CHECK against fork PRs, not a checkout, but the
                # bare `or` treated any `github.event.pull_request.head` mention as proof of an
                # attacker-controlled checkout. Requiring BOTH signals means CRITICAL now needs an
                # untrusted trigger type AND an actual PR-head reference in the same file (the
                # narrower true-positive shape: pull_request_target + an explicit head-ref
                # checkout) -- a trigger alone still surfaces at HIGH via headless-agent-cli-in-ci,
                # never silently dropped.
                trigger_hit = _UNTRUSTED_TRIGGER_RE.search(scan_text)
                head_checkout_hit = _pr_head_checkout(scan_text)
                if trigger_hit and head_checkout_hit:
                    out.append(self._finding(
                        r, "critical", "headless-agent-on-untrusted-trigger", _STD_TRIGGER,
                        f"Headless agent invocation ({hit.group(0).strip()[:80]!r}) in a "
                        f"workflow that runs on an attacker-controllable ref "
                        f"({head_checkout_hit[:80]!r}) — a fork PR's skill/config "
                        "files execute with this repo's secrets, no trust prompt.",
                    ))
                else:
                    out.append(self._finding(
                        r, "medium", "headless-agent-cli-in-ci", _STD_TRIGGER,
                        f"Coding-agent CLI run non-interactively in CI "
                        f"({hit.group(0).strip()[:80]!r}) — the workspace-trust prompt "
                        "is absent, so repo-resident skill/config/tasks files are "
                        "trusted on load.",
                    ))

        for rel_name in _SETTINGS_FILES:
            p = root / rel_name
            if not p.is_file():
                continue
            r = rel(root, p)
            if is_nonproduct_path(r, profile.archive_segments):
                continue
            text = read(p)
            if not text or pragma_present(_PRAGMA, text, dialect=comment_dialect_for(p)):
                continue
            m = _TRUST_FLAG_RE.search(text)
            if m:
                out.append(self._finding(
                    r, "high", "settings-persist-trust", _STD_SETTINGS,
                    f"Checked-in agent settings persist trust/auto-approval "
                    f"({m.group(0).strip()[:60]!r}) — first-use trust survives every "
                    "invocation, including a headless CI run, and travels with a fork.",
                ))

        gemini_files = list(iter_files_named(root, "GEMINI.md")) + [
            f for f in iter_files(root, (".md",)) if ".gemini" in f.parts
        ]
        for p in gemini_files:
            r = rel(root, p)
            if is_nonproduct_path(r, profile.archive_segments):
                continue
            text = read(p)
            if not text or pragma_present(_PRAGMA, text, dialect=comment_dialect_for(p)):
                continue
            m = _SHELL_PAYLOAD_RE.search(text)
            if m:
                out.append(self._finding(
                    r, "critical", "gemini-instruction-shell-payload", _STD_TRIGGER,
                    f"Gemini context/instruction file carries an embedded shell payload "
                    f"({m.group(0).strip()[:40]!r}) — Gemini auto-loads it as context and "
                    "a 2026 measurement found this surface exploited in 95.5-96.1% of runs.",
                ))
        return out

    def _finding(
        self,
        r: str,
        severity: Literal["critical", "high", "medium"],
        rule_suffix: str,
        standards: list[str],
        message: str,
    ) -> Finding:
        return Finding(
            check_id=self.id,
            severity=severity,
            title=self.title,
            location=r,
            message=message,
            remediation=(
                "Never run a coding-agent CLI headlessly on a workflow trigger where the "
                "checked-out content can be attacker-controlled; remove baked-in "
                "trust/auto-approve flags from checked-in agent settings; and scan "
                "auto-loaded instruction files (GEMINI.md, CLAUDE.md, AGENTS.md) for "
                "embedded shell payloads before they reach an agent session."
            ),
            rule=f"agent-headless-trust-surface/{rule_suffix}",
            standards=list(standards),
        )
