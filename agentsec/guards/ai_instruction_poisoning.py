"""Guard: AI coding assistant configuration contains dangerous or poisoned instructions.

These attacks hijack AI coding tools (Claude Code, Cursor, GitHub Copilot, Codeium, Windsurf)
by injecting malicious instructions into configuration files that the assistant loads
automatically on every session. Four distinct attack surfaces are covered:

**Rule 1 — CEA-SCAN-001: autoApprove: true in Claude Code settings (CRITICAL)**
  `.claude/settings.json` / `.claude/settings.local.json` with `"autoApprove": true` means
  the AI agent executes shell commands, file writes, and network requests without asking the
  user. A single prompt-injection from any untrusted input — a file read, a webpage fetched,
  a git commit message — immediately becomes arbitrary command execution (CVE-2025-53773).

**Rule 2 — AIDE-023: Privilege escalation phrases in AI instruction files (HIGH)**
  `CLAUDE.md`, `AGENTS.md`, `.cursorrules`, `.windsurfrules`, and Copilot instruction files
  may be planted with social-engineering language that instructs the AI to ignore its safety
  guidelines or grant itself unrestricted permissions. This is a prompt-injection attack
  targeting the AI's configuration layer rather than runtime input.

**Rule 3 — CEA-103: Hook command exfiltration (CRITICAL)**
  Claude Code PostToolUse/PreToolUse hooks run automatically after every tool call. An
  attacker who can plant a hook config (supply chain, repo fork, CI environment) can
  silently exfiltrate code, secrets, and tool outputs by embedding a `curl`/`wget` call
  to an attacker-controlled URL.

**Rule 4 — CEA-125: npm preinstall/postinstall exfiltration (HIGH)**
  `package.json` install hooks (`preinstall`/`postinstall`) run automatically on
  `npm install`. Supply chain attacks embed outbound HTTP calls here to exfiltrate
  developer credentials, project files, and environment variables at install time.

Standards: OWASP-LLM:LLM01 (Prompt Injection), OWASP-LLM:LLM07 (System Prompt Leakage /
           Agent Hijacking), OWASP:A05 (Security Misconfiguration).

Suppress any rule with the inline pragma:
  # security: allow-ai-instruction-poisoning
"""
from __future__ import annotations

import re
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import CanaryPlant, Guard, is_nonproduct_path, iter_files_named, pragma_present, read, rel

# Every file this guard reads (Claude settings JSON, `package.json`, Markdown and plain-text instruction
# files) has no comment syntax a view reads, so its pragma is matched on the raw text by contract
# (`dialect=None`, #1040 T5).
_PRAGMA = "# security: allow-ai-instruction-poisoning"
# the own fix (a `#`-prefixed opt-out renders as a literal H1 heading in a published
# SKILL.md/CLAUDE.md, so it doesn't work as an invisible pragma there) landed only on
# `obfuscated_payload_execution.py` — this guard ALSO scans `.md`/`SKILL.md` instruction files
# (Rule 2) and needs the same `<!-- -->` alternative (#679 review, Medium). Scoped to Rule 2's
# own markdown scan only; Rules 1/3/4 read JSON, where `#` is already just a magic-substring
# convention, not a real comment character either way, so widening there would be meaningless.
_PRAGMA_MD = re.compile(
    r"#\s*security:\s*allow-ai-instruction-poisoning"
    r"|<!--\s*security:\s*allow-ai-instruction-poisoning\s*-->"
)

# Per-rule standards (a uniform set across these distinct rules is wrong): autoApprove is
# excessive agency (LLM06); escalation phrases are prompt-injection/poisoning (LLM01); hook
# exfil is an agent-driven data leak (LLM06/A10); npm install-hook is supply chain (LLM03/A08).
# (LLM07:2025 is System Prompt Leakage — not what these rules detect.)
# Rule 1 (autoApprove) also carries OWASP-ASI:ASI01 (Agent Goal Hijack, OWASP Top 10 for Agentic
# Applications 2026): removing the confirmation gate means a prompt injection reachable through
# any tool call redirects the agent's objective straight into unrestricted execution — see
# wiki/research/owasp-asi-2026.md.
_STD_AUTO = ["OWASP-LLM:LLM06", "OWASP:A05", "OWASP-ASI:ASI01"]
_STD_ESCALATION = ["OWASP-LLM:LLM01", "OWASP:A05"]
_STD_HOOK = ["OWASP-LLM:LLM06", "OWASP:A10"]
_STD_PKG = ["OWASP-LLM:LLM03", "OWASP:A08"]

# Rule 1: autoApprove: true in Claude settings JSON
# Match the JSON key-value pair; skip comment-like lines (// prefix)
_AUTO_APPROVE = re.compile(r'"autoApprove"\s*:\s*true')
_COMMENT_LINE = re.compile(r'^\s*//')

# Rule 2: privilege-escalation phrases. Each pattern requires an OVERRIDE VERB co-located with a
# SAFETY/PERMISSION OBJECT in the same clause — so operational guidance ("you have access to the
# tools", "commit without asking") does NOT match; only language that tells the AI to remove or
# override its safeguards does. (PR #223 review — the old broad phrases fired on ~9/10 legit lines.)
_ESCALATION_PATTERNS: list[re.Pattern[str]] = [
    re.compile(
        r'\b(?:ignore|disregard|override|forget)\b[^.\n]{0,40}'
        r'\b(?:previous|prior|all\s+(?:previous|prior)|safety|guardrail|safeguard|system\s+prompt'
        r'|your\s+(?:instruction|rule|guideline|safety|constraint|directive))',
        re.IGNORECASE,
    ),
    re.compile(
        r'\b(?:bypass|disable|turn\s+off|circumvent|skip|remove)\b[^.\n]{0,40}'
        r'\b(?:safety|guardrail|safeguard|security\s+(?:check|review|control)|restriction|protection)',
        re.IGNORECASE,
    ),
    re.compile(
        r'\b(?:grant|give|assign)\s+yourself\b[^.\n]{0,30}'
        r'\b(?:permission|access|privilege|root|admin|control)',
        re.IGNORECASE,
    ),
    re.compile(r'\b(?:unrestricted|unlimited)\s+(?:access|permission|control|power|privilege)', re.IGNORECASE),
    re.compile(
        r'run\s+any\s+(?:command|code|tool)[^.\n]{0,30}'
        r'\b(?:without|no|bypass)\b[^.\n]{0,20}'
        r'\b(?:restriction|approval|confirmation|permission|limit|sandbox)',
        re.IGNORECASE,
    ),
    re.compile(r'\bno\s+(?:restrictions?|limits?|guardrails?|safety\s+\w+)\b[^.\n]{0,20}\b(?:apply|exist|in\s+place)', re.IGNORECASE),
]

# A prohibition/negation earlier in the line flips the meaning ("do not bypass security",
# "never ignore policy") — such lines are guidance, not poisoning.
_NEGATION = re.compile(r'\b(?:do not|don\'t|never|must not|cannot|can\'t|avoid|without ever)\b', re.IGNORECASE)

# A "meta-discussion" lead-in earlier in the line ("instructions like X", "patterns such as X",
# "for example X", "e.g. X") means the line DESCRIBES what an attack pattern looks like --
# documentation, a checklist item, a threat-model doc -- rather than ISSUING one. Same
# "quoted, not live" shape `_NEGATION` already covers for guidance language, applied at the
# escalation-match site instead. Confirmed real (#679 review, High): this repo's own
# `claude-skills/security-audit/SKILL.md` fired on "...adversarial injection patterns
# (instructions like "Ignore previous" or role-override attempts)?" -- a checklist item
# describing the threat, not an actual poisoning instruction.
#
# Deliberately narrow (a handful of specific descriptive lead-ins), NOT a general "any quoted
# text is safe" rule -- that would defeat the purpose of Rule 2 differently: a real poisoned
# instruction quoted as a fake authoritative message (`> SYSTEM: "ignore all previous
# instructions"`) has no meta-discussion lead-in and must still fire. Known, disclosed
# bypass: a determined attacker could still prepend "for example" to a live instruction to
# evade this — the same static-keyword-detection limitation every guard in this family
# already carries, not something this fix claims to close.
_META_DISCUSSION = re.compile(
    r'\b(?:instructions?|patterns?|phrases?|examples?|attempts?)\s+(?:like|such\s+as)\b'
    r'|\bfor\s+example\b|\be\.g\.',
    re.IGNORECASE,
)


def _strip_md_code(text: str) -> str:
    """Blank fenced code blocks (preserving line count) and inline-code spans so a CLAUDE.md that
    QUOTES a poisoned snippet as an example doesn't fire (PR #223 review)."""
    text = re.sub(r"```.*?```", lambda m: "\n" * m.group(0).count("\n"), text, flags=re.DOTALL)
    text = re.sub(r"`[^`\n]*`", "", text)
    return text


# Rule 3: hook exfiltration — presence of "hooks" key + curl/wget to external URL
_HOOKS_KEY = re.compile(r'"hooks"')
_EXFIL_PATTERN = re.compile(
    r'(?:curl|wget)\s+["\']?https?://(?!localhost|127\.0\.0\.1|\[::1\])',
    re.IGNORECASE,
)

# Rule 4: npm preinstall/postinstall with external curl/wget
_PKG_INSTALL_HOOK = re.compile(
    r'"(?:pre|post)install"\s*:\s*"[^"]*(?:curl|wget)[^"]*https?://',
    re.IGNORECASE,
)

# AI instruction file names (exact matches only — not suffix-based)
_INSTRUCTION_FILE_NAMES = (
    "CLAUDE.md",
    "AGENTS.md",
    ".cursorrules",
    ".windsurfrules",
)

# AI instruction files matched by path pattern (relative path suffix checks)
_INSTRUCTION_PATH_SUFFIXES = (
    ".github/copilot-instructions.md",
    ".codeium/instructions.md",
)

# Claude settings files
_CLAUDE_SETTINGS_NAMES = (
    "settings.json",
    "settings.local.json",
)


def _is_claude_settings(root: Path, f: Path) -> bool:
    """True if `f` is a Claude settings JSON in a .claude/ directory."""
    try:
        parts = f.relative_to(root).parts
    except ValueError:
        return False
    # Must be inside a .claude/ directory (anywhere in the tree)
    return ".claude" in parts and f.suffix == ".json" and "settings" in f.stem


def _is_instruction_file(root: Path, f: Path) -> bool:
    """True if `f` is an AI instruction file we scan for escalation phrases."""
    if f.name in _INSTRUCTION_FILE_NAMES:
        return True
    try:
        rel_str = str(f.relative_to(root)).replace("\\", "/")
    except ValueError:
        return False
    return any(rel_str.endswith(suf) for suf in _INSTRUCTION_PATH_SUFFIXES)


def _skill_files(root: Path) -> list[Path]:
    """`SKILL.md` files, scanned **regardless of `.gitignore`**.

    A `SKILL.md` is read and acted on by the model exactly like `CLAUDE.md`/`AGENTS.md` (#606's
    own stated reasoning), so Rule 2's escalation-phrase check should reach it same as those. Kept
    off `_INSTRUCTION_FILE_NAMES`/the default `candidate_names` walk on purpose: `.claude/` — where
    a skill bundle actually lives — is routinely gitignored, and the default
    `respect_gitignore=True` would silently produce zero findings on a poisoned skill pulled from a
    public registry into a gitignored `.claude/skills/`, the exact clean-looking-miss shape
    `claude_code_compromise._skill_files()` was built to close for its own two rules (#606 review
    round 2, H1) — same fix, same file, third guard. `_strip_md_code` is safe to keep applying here
    (unlike the shell-chain rule's fence-stripping, which #606's own H1 measured as unsafe): Rule 2
    reads escalation PROSE, not executable syntax, so a fenced code example inside a SKILL.md is the
    same "quoted, not live" case `_strip_md_code` already exists to exempt for CLAUDE.md."""
    return iter_files_named(root, "SKILL.md", respect_gitignore=False)


def _claude_settings_by_dir(root: Path, profile: StackProfile) -> dict[str, list[Path]]:
    """`*settings*.json` files under product `.claude/` dirs, keyed by each file's nearest `.claude` dir.

    Enumerated through the shared walker, not `root.rglob(".claude")` (#1042). That walked the whole
    repo, `.venv`/`node_modules` included, and reported a nested worktree's own
    `.claude/worktrees/<branch>/.claude/settings.json` as a second copy of the same finding.
    `respect_gitignore=False` because `settings.local.json` is routinely gitignored and is exactly
    what Rules 1 and 3 audit.

    The non-product check sees the OUTERMOST `.claude` ancestor's path. The old per-dir walk scanned
    a file when any `.claude` ancestor was product, and an inner `.claude` path only adds segments to
    the outer one's, so the outer decides. The KEY is the NEAREST `.claude` ancestor: Rule 3 reports
    one finding per key, which keeps the old one-per-`.claude`-dir cap for a nested (non-worktree)
    `.claude/` too, without the old walk's second report of the inner file from the outer dir.
    """
    groups: dict[str, list[Path]] = {}
    for f in iter_files_named(root, "*.json", respect_gitignore=False):
        if "settings" not in f.stem:
            continue
        parents = f.relative_to(root).parts[:-1]
        if ".claude" not in parents:
            continue
        outermost = "/".join(parents[: parents.index(".claude") + 1])
        if is_nonproduct_path(outermost, profile.archive_segments):
            continue
        nearest = len(parents) - parents[::-1].index(".claude")
        groups.setdefault("/".join(parents[:nearest]), []).append(f)
    return groups


class AiInstructionPoisoningGuard(Guard):
    id = "ai-instruction-poisoning"
    title = "AI coding assistant configuration contains dangerous or poisoned instructions"
    area = "AI agent"

    # Canary plant: EXPECTS-ONLY — no `files`. The violation is planted in the canary's shared
    # `.claude/settings.json` (which `tool-callback-enforcement` also trips), so that file stays in
    # `canary.py`'s base owned by no guard. The ownership rule this follows is documented on
    # `xxe_safe.py`.
    # .claude/settings.json: "autoApprove": true -> fires auto-approve-enabled (CRITICAL).
    canary_plant = CanaryPlant(expects=frozenset({"ai-instruction-poisoning/auto-approve-enabled"}))

    def applies(self, profile: StackProfile) -> bool:  # noqa: ARG002
        return True

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []
        out.extend(self._rule1_auto_approve(root, profile))
        out.extend(self._rule2_escalation(root, profile))
        out.extend(self._rule3_hook_exfil(root, profile))
        out.extend(self._rule4_package_hook_exfil(root, profile))
        return out

    # ------------------------------------------------------------------
    # Rule 1 — CEA-SCAN-001: autoApprove: true in Claude settings
    # ------------------------------------------------------------------
    def _rule1_auto_approve(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []
        for settings_files in _claude_settings_by_dir(root, profile).values():
            for f in settings_files:
                text = read(f)
                if not text or pragma_present(_PRAGMA, text, dialect=None):
                    continue
                for i, line in enumerate(text.splitlines(), 1):
                    # Skip comment-like lines (JSON doesn't support // comments but
                    # some editors / tools pre-process them)
                    if _COMMENT_LINE.match(line):
                        continue
                    if _AUTO_APPROVE.search(line):
                        out.append(Finding(
                            check_id=self.id,
                            severity="critical",
                            title="Claude Code autoApprove enabled — unrestricted tool execution",
                            location=f"{rel(root, f)}:{i}",
                            rule="ai-instruction-poisoning/auto-approve-enabled",
                            standards=list(_STD_AUTO),
                            message=(
                                "autoApprove: true grants the AI agent unrestricted tool execution "
                                "without user confirmation. Any prompt injection attack immediately "
                                "becomes arbitrary command execution (CVE-2025-53773)."
                            ),
                            remediation=(
                                "Remove autoApprove: true from Claude settings. Require explicit "
                                "approval for all tool calls, especially shell commands, file "
                                "writes, and network requests."
                            ),
                        ))
                        break  # one finding per file
        return out

    # ------------------------------------------------------------------
    # Rule 2 — AIDE-023: Privilege escalation phrases in AI instruction files
    # ------------------------------------------------------------------
    def _rule2_escalation(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []
        # Find all candidate instruction files by name
        candidate_names = list(_INSTRUCTION_FILE_NAMES) + [
            "copilot-instructions.md",
            "instructions.md",
        ]
        for f in [*iter_files_named(root, *candidate_names), *_skill_files(root)]:
            if not (f.name == "SKILL.md" or _is_instruction_file(root, f)):
                continue
            r = rel(root, f)
            if is_nonproduct_path(r, profile.archive_segments):
                continue
            text = read(f)
            if not text or pragma_present(_PRAGMA_MD, text, dialect=None):
                continue
            for i, line in enumerate(_strip_md_code(text).splitlines(), 1):
                m = next((p.search(line) for p in _ESCALATION_PATTERNS if p.search(line)), None)
                if not m:
                    continue
                # A negation earlier in the line makes it guidance, not poisoning.
                neg = _NEGATION.search(line)
                if neg and neg.start() < m.start():
                    continue
                # A meta-discussion lead-in earlier in the line means the line describes the
                # attack pattern rather than issuing it (see _META_DISCUSSION docstring).
                meta = _META_DISCUSSION.search(line)
                if meta and meta.start() < m.start():
                    continue
                out.append(Finding(
                    check_id=self.id,
                    severity="high",
                    title="AI instruction file contains a privilege-escalation / safety-override instruction",
                    location=f"{r}:{i}",
                    rule="ai-instruction-poisoning/privilege-escalation-instruction",
                    standards=list(_STD_ESCALATION),
                    message=(
                        "AI instruction file contains language that instructs the AI agent to "
                        "override or disable its safety guardrails, or to grant itself unrestricted "
                        "permissions. This is a social-engineering injection at the configuration layer."
                    ),
                    remediation=(
                        "Remove the safety-override / privilege-escalation language. AI agents "
                        "should operate under least privilege — explicit permission per action "
                        "type, not blanket authorization or self-granted access."
                    ),
                ))
                break  # one finding per file
        return out

    # ------------------------------------------------------------------
    # Rule 3 — CEA-103: Hook command exfiltration in Claude settings
    # ------------------------------------------------------------------
    def _rule3_hook_exfil(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []
        for settings_files in _claude_settings_by_dir(root, profile).values():
            for f in settings_files:
                text = read(f)
                if not text or pragma_present(_PRAGMA, text, dialect=None):
                    continue
                # Must have a "hooks" key AND the exfil call on a hook COMMAND line — so an
                # unrelated `curl` in an "env"/other setting doesn't fire (PR #223 review).
                if not _HOOKS_KEY.search(text):
                    continue
                loc_line = None
                for i, line in enumerate(text.splitlines(), 1):
                    if '"command"' in line and _EXFIL_PATTERN.search(line):
                        loc_line = i
                        break
                if loc_line is None:
                    continue
                out.append(Finding(
                    check_id=self.id,
                    severity="critical",
                    title="Claude Code hook exfiltrates data via an external HTTP call",
                    location=f"{rel(root, f)}:{loc_line}",
                    rule="ai-instruction-poisoning/hook-exfiltration",
                    standards=list(_STD_HOOK),
                    message=(
                        "Claude Code hook configuration contains a curl/wget command to an "
                        "external URL. PostToolUse hooks with outbound HTTP calls can silently "
                        "exfiltrate code, secrets, and tool outputs to attacker-controlled "
                        "infrastructure."
                    ),
                    remediation=(
                        "Remove external HTTP calls from hook commands. Hooks should only invoke "
                        "local scripts. Review all hook configurations for data exfiltration "
                        "patterns."
                    ),
                ))
                break  # one finding per settings file
        return out

    # ------------------------------------------------------------------
    # Rule 4 — CEA-125: npm preinstall/postinstall exfiltration
    # ------------------------------------------------------------------
    def _rule4_package_hook_exfil(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []
        for f in iter_files_named(root, "package.json"):
            r = rel(root, f)
            if is_nonproduct_path(r, profile.archive_segments):
                continue
            text = read(f)
            if not text or pragma_present(_PRAGMA, text, dialect=None):
                continue
            for i, line in enumerate(text.splitlines(), 1):
                if _PKG_INSTALL_HOOK.search(line):
                    out.append(Finding(
                        check_id=self.id,
                        severity="high",
                        title="npm install hook exfiltrates data (supply-chain)",
                        location=f"{r}:{i}",
                        rule="ai-instruction-poisoning/package-hook-exfil",
                        standards=list(_STD_PKG),
                        message=(
                            "package.json preinstall/postinstall script contains an outbound HTTP "
                            "request. Supply chain attacks embed data exfiltration in install hooks "
                            "— this runs automatically on 'npm install'."
                        ),
                        remediation=(
                            "Remove HTTP calls from install scripts. If you need setup scripts, "
                            "use local script files without network calls."
                        ),
                    ))
                    break  # one finding per package.json
        return out
