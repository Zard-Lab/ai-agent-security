"""Guard: LLM output must not flow into a code/command sink (checklist 4-llm-output-not-executed).

The defining agentic-era RCE: an app asks the model for something, then runs the
answer. `exec(agent.run_sync(prompt))`, `os.system(llm.invoke(task))`,
`eval(chat.completions.create(...))` — the model's output (which an attacker can
steer via prompt injection) becomes code or a shell command. Agentic CVEs are the
fastest-growing class precisely because models now drive execution.

Three statically detectable patterns:

  1. **`model-output-executed`** (HIGH): An LLM call expression sits directly inside
     a code/command sink (`exec` / `eval` / `compile` / `os.system` / `subprocess.*`)
     on one line. The fix is to never execute model output: parse it, validate against
     an allowlist, or route through a constrained tool layer.

  2. **`eval-variable-mediated`** (HIGH): In files that contain an LLM call, `eval()`
     or `exec()` is called with a bare variable name (not a string literal). The
     variable is likely the stored result of a prior LLM call (the two-line pattern:
     `response = llm.invoke(prompt); eval(response)`). Catches the multi-line case that
     pattern 1 misses.

  3. **`sql-execute-variable`** (HIGH): In files that contain an LLM call,
     `cursor.execute()` / `connection.execute()` / etc. is called with a non-literal
     first argument (a variable name or f-string). When LLM output flows into SQL
     this way, a prompt-injection attack becomes SQL injection.

A reviewed sandboxed case can suppress a line with `# security: allow-llm-sink`.

OWASP-LLM:LLM05 (Insecure Output Handling) / CWE-94. Gated on `llm`.
"""
from __future__ import annotations

import re
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import (
    CanaryPlant,
    Guard,
    is_nonproduct_path,
    iter_files,
    pragma_line_set,
    python_scan_dirs,
    read,
    rel,
    strip_python_strings,
)

_STANDARDS = ["OWASP-LLM:LLM05", "OWASP:A03"]

# A code/command sink whose argument contains an LLM call expression (call-form, one line).
_LLM_IN_SINK = re.compile(
    r"\b(?:exec|eval|compile|os\.system|subprocess\.(?:run|call|check_output|Popen)|"
    r"commands\.getoutput)\s*\([^)\n]*"
    r"(?:\.run_sync\(|\.run\(|\.ainvoke\(|\.invoke\(|\.predict\(|\.generate\(|\.complete\(|"
    r"completions\.create\()",
    re.I,
)
_PRAGMA = re.compile(r"#\s*security:\s*allow-llm-sink")

# Detect an LLM *call* anywhere in the file (gates the per-file checks). Deliberately
# call-shaped, not substring: bare `.run(`/`.generate(`/`.complete(` (which match test
# runners / generic generators) and the `openai.`/`anthropic.` import substrings are NOT
# accepted — only real LLM call/client forms.
_LLM_CALL_ANYWHERE = re.compile(
    r"\.(?:run_sync|ainvoke|invoke|arun)\s*\("
    r"|\b(?:agent|llm|chain|model|client|graph)\w*\.(?:run|generate|complete|predict)\s*\("
    r"|chat\.completions\.create\s*\("
    r"|\.messages\.create\s*\("
    r"|\b(?:OpenAI|AsyncOpenAI|Anthropic|AsyncAnthropic|ChatOpenAI|ChatAnthropic)\s*\(",
    re.I,
)

# A variable assigned (on one line) from an LLM call — the data that must not reach a sink.
_LLM_ASSIGN = re.compile(
    r"^\s*([A-Za-z_]\w*)\s*=\s*.*"
    r"(?:\.(?:run_sync|ainvoke|invoke|arun)\s*\(|chat\.completions\.create\s*\(|\.messages\.create\s*\(|"
    r"\b(?:agent|llm|chain|model|client|graph)\w*\.(?:run|generate|complete|predict)\s*\()",
    re.I,
)

# eval()/exec() called with a bare variable. `(?<![.\w])` anchors the BUILTIN form so
# method calls like `df.eval(...)` / `numexpr.evaluate(...)` do NOT match.
_EVAL_VAR = re.compile(
    r"(?<![.\w])(?:eval|exec)\s*\(\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*\)",
    re.I,
)

# Identifiers that are always safe — built-in constants, not variables holding LLM output.
_SAFE_IDENTIFIERS = frozenset({"True", "False", "None"})

# A DB execute() call (receiver in the known set). The first arg is inspected separately:
# we fire only on a dynamically-BUILT SQL string or a variable proven to hold LLM output,
# NOT on a bare literal, a parameterized call, or a SQLAlchemy Core construct.
_SQL_EXECUTE_CALL = re.compile(
    r"\b(?:cursor|cur|conn|connection|session|db|engine)\s*\.\s*execute\s*\(\s*(.*)$",
    re.I,
)
# Genuine SQL string-building in the execute() argument: an f-string, string concatenation,
# or .format(). (`%` is excluded: `%s` is a *parameter* placeholder, not interpolation.)
_SQL_DYNAMIC_ARG = re.compile(r"""f["']|["']\s*\+|\+\s*["']|\.format\s*\(""")
# A bare leading identifier (the first arg is just `var)` / `var,`).
_BARE_FIRST_ARG = re.compile(r"^([A-Za-z_]\w*)\s*[),]")

# Strip the content of single-line single- and double-quoted string literals so that
# pattern examples in docstrings and message strings don't produce false positives
# when the guard scans its own source file. Backtick-quoted markdown spans inside
# triple-quoted strings are handled by strip_python_strings(); this covers the
# single-line case (e.g., message="...eval(response)...").
_SINGLE_LINE_STR = re.compile(
    r'(?<!\\)(?:\"(?:[^\"\\]|\\.)*\"|\'(?:[^\'\\]|\\.)*\')'
)


def _blank_string_contents(line: str) -> str:
    """Replace the contents of single-line string literals with spaces (preserving quotes).

    This prevents guard patterns from matching example code written inside Python string
    literals (e.g., a Finding's `message=` parameter that contains `eval(response)`).
    Triple-quoted strings are handled separately by `strip_python_strings`.
    """
    def _blank(m: re.Match[str]) -> str:
        s = m.group()
        # Keep the opening and closing quote, blank the interior.
        return s[0] + " " * (len(s) - 2) + s[-1]
    return _SINGLE_LINE_STR.sub(_blank, line)


class LlmOutputToSinkGuard(Guard):
    id = "llm-output-to-sink"
    title = "LLM output flows into a code/command sink — model-driven RCE"
    area = "AI agent"

    # Canary plant: EXPECTS-ONLY — no `files`. The violation is planted across the canary's shared
    # `llm_eval_sink.py`, `llm_sql_sink.py` and `tools.py`, each of which several guards trip at once, so
    # those files stay in `canary.py`'s base owned by no guard. The ownership rule this follows is documented
    # on `xxe_safe.py`.
    # tools.py: exec(agent.run_sync(task)) -> model output executed.
    # llm_eval_sink.py: eval(code) where code = agent.run_sync(prompt).data -> eval-variable-mediated.
    # llm_sql_sink.py: cursor.execute(sql_query) where sql_query comes from LLM -> sql-execute-variable.
    canary_plant = CanaryPlant(expects=frozenset({
        "llm-output-to-sink/model-output-executed",
        "llm-output-to-sink/eval-variable-mediated",
        "llm-output-to-sink/sql-execute-variable",
    }))

    def applies(self, profile: StackProfile) -> bool:
        return "llm" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []
        seen: set[Path] = set()
        for d in python_scan_dirs(root, profile):
            for f in iter_files(d, (".py",)):
                if f in seen:
                    continue
                seen.add(f)
                text = read(f)
                rel_path = rel(root, f)
                if is_nonproduct_path(rel_path, profile.archive_segments):
                    continue
                # Blank triple-quoted docstrings up front so pattern 1 (model-output-executed)
                # doesn't fire on the anti-pattern EXAMPLES in this guard's own docstring (#424);
                # patterns B/C already scanned this stripped text.
                stripped_text = strip_python_strings(text, filename=f)
                stripped_lines = stripped_text.splitlines()
                # All three patterns skip a line whose pragma is a real comment, never the phrase
                # in a string there (#1040), numbered on the text walked below (a form feed in a
                # docstring shifts the raw count, #1132).
                pragmas = pragma_line_set(_PRAGMA, stripped_text, dialect="python")
                for i, line in enumerate(stripped_lines, start=1):
                    if line.lstrip().startswith("#") or i in pragmas:
                        continue
                    # Blank single-line string contents too, so a sink pattern quoted inside a
                    # message= string doesn't self-match (parity with patterns B/C below).
                    if _LLM_IN_SINK.search(_blank_string_contents(line)):
                        out.append(
                            Finding(
                                check_id=self.id,
                                severity="high",
                                title=self.title,
                                location=f"{rel_path}:{i}",
                                message=(
                                    "Model output is passed straight into a code/command sink "
                                    "(exec/eval/os.system/subprocess). An attacker who steers the "
                                    "model via prompt injection gets remote code or command execution."
                                ),
                                remediation=(
                                    "Never execute model output. Parse and validate it, constrain it "
                                    "to an allowlist, or route actions through a typed tool layer with "
                                    "its own authorization. If genuinely sandboxed, suppress with "
                                    "`# security: allow-llm-sink`."
                                ),
                                rule="llm-output-to-sink/model-output-executed",
                                standards=list(_STANDARDS),
                            )
                        )
                # Patterns B and C: only scan files that have an LLM call somewhere. The
                # docstring blanking above (stripped_text/stripped_lines) is reused here.
                if not _LLM_CALL_ANYWHERE.search(stripped_text):
                    continue
                # Variables assigned from an LLM call — the data that must not reach a sink.
                llm_vars = {m.group(1) for ln in stripped_lines if (m := _LLM_ASSIGN.match(ln))}
                out += self._check_eval_variable(rel_path, stripped_lines, pragmas)
                out += self._check_sql_execute(rel_path, stripped_lines, llm_vars, pragmas)
        return out

    def _check_eval_variable(
        self,
        rel_path: str,
        lines: list[str],
        pragmas: frozenset[int],
    ) -> list[Finding]:
        findings: list[Finding] = []
        for i, line in enumerate(lines, start=1):
            if line.lstrip().startswith("#") or i in pragmas:
                continue
            # Blank single-line string contents so patterns in message strings
            # (e.g., 'eval(response)' in a Finding message) do not fire.
            scan_line = _blank_string_contents(line)
            m = _EVAL_VAR.search(scan_line)
            if m:
                ident = m.group(1)
                if ident in _SAFE_IDENTIFIERS:
                    continue
                findings.append(
                    Finding(
                        check_id=self.id,
                        severity="high",
                        title="eval()/exec() called on a variable in an LLM-using file",
                        location=f"{rel_path}:{i}",
                        message=(
                            f"eval() or exec() is called with a bare variable (`{ident}`) in a file "
                            "that also makes LLM calls. This is the two-line RCE pattern: "
                            "`response = llm.invoke(prompt)` then `eval(response)`. A prompt-injection "
                            "attacker can steer the LLM output into arbitrary code execution."
                        ),
                        remediation=(
                            "Never execute model output. Parse and validate it, constrain it to an "
                            "allowlist, or route actions through a typed tool layer with its own "
                            "authorization. If genuinely sandboxed, suppress with "
                            "`# security: allow-llm-sink`."
                        ),
                        rule="llm-output-to-sink/eval-variable-mediated",
                        standards=list(_STANDARDS),
                    )
                )
        return findings

    def _check_sql_execute(
        self,
        rel_path: str,
        lines: list[str],
        llm_vars: set[str],
        pragmas: frozenset[int],
    ) -> list[Finding]:
        findings: list[Finding] = []
        for i, line in enumerate(lines, start=1):
            if line.lstrip().startswith("#") or i in pragmas:
                continue
            scan_line = _blank_string_contents(line)
            m = _SQL_EXECUTE_CALL.search(scan_line)
            if not m:
                continue
            arg = m.group(1)  # text after `execute(` (string contents already blanked)
            # Fire only when the SQL is genuinely attacker-influenceable:
            #   (a) it is built as a dynamic string (f-string / concat / .format), OR
            #   (b) the first argument is a bare variable proven to hold LLM output.
            # This deliberately does NOT fire on a bare literal, a parameterized call
            # (`execute(QUERY, params)`), or a SQLAlchemy Core construct (`select(...)`).
            dynamic = bool(_SQL_DYNAMIC_ARG.search(arg))
            bare = _BARE_FIRST_ARG.match(arg)
            llm_derived = bool(bare and bare.group(1) in llm_vars)
            if not (dynamic or llm_derived):
                continue
            findings.append(
                Finding(
                    check_id=self.id,
                    severity="high",
                    title="LLM-derived or dynamically-built SQL passed to execute() in an LLM-using file",
                    location=f"{rel_path}:{i}",
                    message=(
                        "A database execute() call receives a dynamically-built SQL string "
                        "(f-string / concatenation / .format) or a variable that holds LLM "
                        "output, in a file that makes LLM calls. When model output flows into "
                        "SQL this way, a prompt-injection attack becomes SQL injection."
                    ),
                    remediation=(
                        "Use parameterized queries: pass the SQL as a literal string and supply "
                        "values as a separate argument (execute('SELECT ... WHERE id=%s', (val,))). "
                        "For SQLAlchemy use bound params / Core constructs. Never interpolate or "
                        "concatenate LLM output into a SQL string. Suppress with "
                        "`# security: allow-llm-sink` only if the SQL is provably not LLM-derived."
                    ),
                    rule="llm-output-to-sink/sql-execute-variable",
                    standards=list(_STANDARDS),
                )
            )
        return findings
