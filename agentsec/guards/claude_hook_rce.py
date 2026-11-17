"""Guard: a Claude Code hook command interpolates a shell variable with no quoting, or is
defined in `.claude/settings.local.json` rather than the checked-in, reviewed `settings.json` —
CVE-2025-59536 (checklist §8, new item; agent-audit-kit's `hook_rce.py` AAK-HOOK-RCE-001/003).

Claude Code hooks (`.claude/settings.json`'s `hooks` key: `PreToolUse`/`PostToolUse`/etc, each
mapping to `[{"matcher": ..., "hooks": [{"type": "command", "command": "..."}]}]`) run a shell
command on tool-use events. CVE-2025-59536 disclosed two ways this becomes remote code execution:

  1. **`unquoted-variable-interpolation`** (HIGH): a hook's `command` string interpolates a shell
     variable (`$VAR`/`${VAR}`) with NO surrounding quotes at all. An unquoted expansion is
     subject to word-splitting and glob expansion — if the variable's value is attacker/tool-input
     influenced and contains whitespace or shell metacharacters, it can inject additional
     arguments or commands. (A `"$VAR"` — double-quoted — expansion is the safer idiom this rule
     does not flag; word-splitting/globbing is suppressed, though command substitution inside the
     value is still possible — see "Known bypasses".)
  2. **`settings-local-hooks-pre-trust`** (HIGH): `.claude/settings.local.json` — the personal,
     typically-gitignored override file, NOT the checked-in `settings.json` a team reviews —
     itself defines a `hooks` key. A hook planted there runs on the next tool-use event without
     going through the same review path a checked-in `settings.json` change would.

**Deliberately not ported: a third AAK rule** (`shell:true`/dynamic-string execution in an
externally-referenced hook SCRIPT's own source) — that requires resolving and reading whatever
file the hook's `command` field points at (an external, potentially non-Python/JSON file with its
own language and quoting rules), which is a different, already-covered concern
(`js-command-injection`/`command_injection` already flag `shell: true`/`shell=True` with a dynamic
command in the SCRIPT itself, wherever it lives) rather than something specific to the hook
JSON wiring this guard focuses on.

Suppress an audited case with a top-level `"//": "security: allow-claude-hook-rce"` string
anywhere in the JSON document (JSON has no comment syntax).
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from agentsec.detect import StackProfile
from agentsec.findings import Finding, Severity

from .base import CanaryPlant, Guard, is_nonproduct_path, iter_files_named, pragma_present, read, rel

# `.claude/settings*.json` has no comment syntax (the documented opt-out is a `"//"` string value), so its
# pragma is matched on the raw text by contract (`dialect=None`, #1040 T5).
_PRAGMA = "security: allow-claude-hook-rce"

_STD_UNQUOTED = ["CWE-78", "CWE-88"]
_STD_LOCAL_HOOKS = ["CWE-284", "OWASP:A01"]


def _load(raw: str) -> dict[str, Any] | None:
    try:
        data = json.loads(raw)
    except (ValueError, RecursionError):  # a deeply nested file must not crash the guard
        return None
    return data if isinstance(data, dict) else None


def _iter_hook_commands(data: dict[str, Any]) -> list[str]:
    """Every `command` string under `hooks.<event>[*].hooks[*]`."""
    out: list[str] = []
    hooks = data.get("hooks")
    if not isinstance(hooks, dict):
        return out
    for entries in hooks.values():
        if not isinstance(entries, list):
            continue
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            inner = entry.get("hooks")
            if not isinstance(inner, list):
                continue
            for h in inner:
                if isinstance(h, dict) and isinstance(h.get("command"), str):
                    out.append(h["command"])
    return out


def _unquoted_variable_refs(command: str) -> list[str]:
    """`$VAR`/`${VAR}` references in `command` that sit OUTSIDE any single- or double-quoted
    span — a real quote-state walk (not a per-character lookaround), so a variable in the middle
    of a longer double-quoted string (`"prefix $VAR suffix"`) is correctly recognized as quoted."""
    out: list[str] = []
    quote: str | None = None
    i, n = 0, len(command)
    while i < n:
        ch = command[i]
        if quote:
            if ch == "\\" and quote == '"':
                i += 2
                continue
            if ch == quote:
                quote = None
            i += 1
            continue
        if ch in "'\"":
            quote = ch
            i += 1
            continue
        if ch == "$" and i + 1 < n and (command[i + 1].isalpha() or command[i + 1] in "_{"):
            start = i
            i += 1
            if i < n and command[i] == "{":
                i += 1
                while i < n and command[i] != "}":
                    i += 1
                i += 1
            else:
                while i < n and (command[i].isalnum() or command[i] == "_"):
                    i += 1
            out.append(command[start:i])
            continue
        i += 1
    return out


class ClaudeHookRceGuard(Guard):
    id = "claude-hook-rce"
    title = "Claude Code hook command is exploitable — unquoted variable expansion or a pre-trust local hook"
    area = "AI agent"

    # claude-hook-rce-canary/.claude/settings.json: PreToolUse hook command interpolates
    # $CLAUDE_TOOL_INPUT with no quoting -> fires
    # claude-hook-rce/unquoted-variable-interpolation. A nested directory (not the repo-root
    # .claude/settings.json, which canary.py's shared scaffolding already owns for
    # ai-instruction-poisoning) so this guard gets its own unshared plant file.
    canary_plant = CanaryPlant(
        files={
            "claude-hook-rce-canary/.claude/settings.json": (
                '{\n'
                '  "hooks": {\n'
                '    "PreToolUse": [\n'
                '      {\n'
                '        "matcher": "Bash",\n'
                '        "hooks": [\n'
                '          {"type": "command", "command": "echo $CLAUDE_TOOL_INPUT >> /tmp/log"}\n'
                '        ]\n'
                '      }\n'
                '    ]\n'
                '  }\n'
                '}\n'
            ),
        },
        expects=frozenset({
            "claude-hook-rce/unquoted-variable-interpolation",
        }),
    )

    def applies(self, profile: StackProfile) -> bool:  # noqa: ARG002
        return True

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []
        for f in iter_files_named(
            root, "settings.json", "settings.local.json", respect_gitignore=False,
        ):
            if f.parent.name != ".claude":
                continue
            r = rel(root, f)
            if is_nonproduct_path(r, profile.archive_segments):
                continue
            raw = read(f)
            if not raw or pragma_present(_PRAGMA, raw, dialect=None):
                continue
            data = _load(raw)
            if data is None:
                continue

            if f.name == "settings.local.json" and isinstance(data.get("hooks"), dict) and data["hooks"]:
                out.append(self._finding(
                    r, "settings-local-hooks-pre-trust", "high", _STD_LOCAL_HOOKS,
                    "settings.local.json — the personal, typically-gitignored override file, "
                    "not the checked-in settings.json a team reviews — defines hooks. A hook "
                    "planted here runs on the next tool-use event without going through the "
                    "same review path a checked-in settings.json change would.",
                    "Keep hook definitions in the checked-in, reviewed settings.json. Treat any "
                    "hooks key appearing in settings.local.json as suspicious unless you added "
                    "it yourself.",
                ))

            for command in _iter_hook_commands(data):
                for ref in _unquoted_variable_refs(command):
                    out.append(self._finding(
                        r, "unquoted-variable-interpolation", "high", _STD_UNQUOTED,
                        f"Hook command interpolates {ref} with no surrounding quotes: "
                        f"{command!r}. An unquoted shell expansion is subject to word-splitting "
                        "and glob expansion — if the variable's value is influenced by tool "
                        "input and contains whitespace or shell metacharacters, it can inject "
                        "additional arguments or commands (CVE-2025-59536 class).",
                        f'Quote the expansion ("{ref}") to suppress word-splitting and glob '
                        "expansion, and validate/sanitize the variable's value before it "
                        "reaches the hook command at all.",
                    ))
        return out

    def _finding(
        self, r: str, rule_suffix: str, severity: Severity, standards: list[str], message: str,
        remediation: str,
    ) -> Finding:
        return Finding(
            check_id=self.id,
            severity=severity,
            title=self.title,
            location=r,
            message=message,
            remediation=remediation,
            rule=f"claude-hook-rce/{rule_suffix}",
            standards=list(standards),
        )
