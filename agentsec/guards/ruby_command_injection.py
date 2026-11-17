"""Guard: no OS-command injection via a Ruby shell sink (checklist §3b).

The Ruby counterpart to agentsec's existing `command-injection` (Python) and
`js-command-injection` (JS/TS) guards — same requirement (a shell sink fed a string the
attacker can steer is host RCE), a genuinely different code surface (Ruby's `Kernel#system`,
`Kernel#exec`, backtick execution, `%x{}`, `Open3` and `IO.popen` instead of `os.system`/
`subprocess`/`child_process`), so it extends the same `3b-command-injection` checklist item
rather than duplicating it.

Pattern verified against Brakeman's real source (`lib/brakeman/checks/check_execute.rb`,
`Brakeman::CheckExecute`) — the class name and file are cited for provenance; detection logic
and test fixtures here are original, developed independently against the pattern description,
not copied or derived from Brakeman's own (Ruby) implementation.

Fires CRITICAL on a shell sink whose **first argument is a dynamic string**:

  * `system(...)` / `exec(...)` (bareword `Kernel#` form, and the `Kernel.`/`Process.`
    receivers), with or without parentheses (`system "rake #{task}"` is idiomatic Ruby);
  * backtick execution — `` `git clone #{url}` `` — and its `%x{...}` / `%x(...)` / `%x[...]`
    equivalents;
  * `Open3.popen2/popen2e/popen3` and `Open3.capture2/capture2e/capture3` (same shell-vs-argv
    semantics, same sink family);
  * `IO.popen(...)`.

"Dynamic" means the first argument is a **string literal** that is either interpolated
(`"ping #{host}"`) or concatenated (`"git clone " + url`). Ruby's single-quoted strings do not
interpolate, so `'ping #{host}'` is a literal `#` and stays silent unless it is concatenated.

**The argv-array form is the fix, and must stay silent.** `system(["ping", host])`,
`system("ping", host)`, `IO.popen(["ls", dir])` and `Open3.capture3("git", "clone", url)` all
bypass the shell entirely — Ruby execs the program directly, exactly like Python's
`subprocess.run([...])` without `shell=True`. None of those have a dynamic *string* as the
first argument, so the same rule that fires on the shell form is silent on the safe one.

Suppress an audited case with:

    system("rake #{task}")  # security: allow-shell-exec
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
    read,
    rel,
    ruby_scan_dirs,
    strip_ruby_comments,
)

# A call-form shell sink, up to and including its opening delimiter.
#
# The left lookbehinds are the whole false-positive story for the barewords: `(?<![\w.:@$])`
# keeps `conn.exec(sql)` (PG::Connection#exec — the single most common real-world collision
# with `Kernel#exec`), `shell.system(...)` and `@system(...)` out, and `(?<!def )` keeps an
# application's OWN `def exec(cmd)` definition line from reading as a call to Kernel's.
#
# The trailing group accepts both Ruby call forms: `system("...")` (paren) and `system "..."`
# (paren-less, only when the next token actually starts a string literal — `system` used as a
# bare local variable or in `system = ...` must not match).
_SHELL_SINK = re.compile(
    r"(?<![\w.:@$])(?<!def )"
    r"(?:"
    r"(?:(?:Kernel|Process)\s*(?:\.|::)\s*)?(?:system|exec)"
    r"|Open3\s*\.\s*(?:popen2e|popen2|popen3|capture2e|capture2|capture3)"
    r"|IO\s*\.\s*popen"
    r")"
    r"""\s*(?:\(|(?=['"]))"""
)

# Backtick execution and its `%x` equivalents. Both are *literals*, so the whole sink and its
# argument are the same token — a hit is simply "this literal interpolates".
_BACKTICK = re.compile(r"`([^`\n]*)`")
_PERCENT_X = re.compile(
    r"%x(?:\{([^}\n]*)\}|\(([^)\n]*)\)|\[([^\]\n]*)\]|<([^>\n]*)>|\|([^|\n]*)\|)"
)

# `"... #{expr} ..."` — Ruby string interpolation. Only meaningful inside a DOUBLE-quoted
# string; `'#{x}'` is three literal characters.
_INTERP = re.compile(r"#\{")
# A string literal adjacent to `+` — `"git clone " + url`, `url + " --depth 1"`.
_CONCAT = re.compile(r"""['"]\s*\+|\+\s*['"]""")

# Sibling-consistent pragma: the same opt-out token the Python `command-injection` guard
# honours (`ruby-weak-crypto` reuses `allow-weak-crypto` for the same reason — one pragma per
# requirement, not one per language).
_PRAGMA = re.compile(r"#\s*security:\s*allow-shell-exec")


def _first_arg(text: str) -> str:
    """Return the source text of the first top-level argument in `text`, which starts just
    after a call's opening delimiter. Stops at the first top-level `,` or closing bracket,
    tracking quotes and nesting so `system("ls", dir)` yields `"ls"` and
    `system(["ls", dir])` yields `["ls", dir]`."""
    out: list[str] = []
    depth = 0
    quote = ""
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        if quote:
            out.append(c)
            if c == "\\" and i + 1 < n:
                out.append(text[i + 1])
                i += 2
                continue
            if c == quote:
                quote = ""
            i += 1
            continue
        if c in "\"'":
            quote = c
            out.append(c)
            i += 1
            continue
        if c in "([{":
            depth += 1
        elif c in ")]}":
            if depth == 0:
                break
            depth -= 1
        elif c == "," and depth == 0:
            break
        out.append(c)
        i += 1
    return "".join(out)


def _is_dynamic(arg: str) -> bool:
    """True when `arg` is a shell command STRING assembled at runtime.

    Deliberately narrow, and the narrowness is what makes the safe form silent for free:

    * an argv array (`["ping", host]`) or a splat (`*argv`) is never a shell string — those
      are the FIX, and they are excluded up front;
    * `#{` counts only for a literal that OPENS with a double quote (Ruby's single quotes do
      not interpolate, so `'echo #{x}'` is three literal characters);
    * `+` adjacent to a string literal anywhere in the argument is concatenation — this has to
      accept `cmd + " --depth 1"` as well as `"git clone " + url`, so it cannot require the
      argument to START with the literal (caught by the adversarial self-test: requiring a
      leading quote silently missed every literal-on-the-right concatenation);
    * a bare variable with no literal at all (`system(cmd)`) stays silent — in Ruby that
      variable may equally hold the SAFE argv array, which is not true of the Python sibling's
      `os.system(cmd)`. Documented as a known false negative rather than guessed at.
    """
    a = arg.strip()
    if not a or a.startswith(("[", "*")):
        return False
    if a.startswith('"') and _INTERP.search(a):
        return True
    return bool(_CONCAT.search(a))


def _live(raw: str, code: str, idx: int) -> bool:
    """True when the character at `idx` survived comment stripping — i.e. the match is real
    code and not text inside a `#` comment or a `=begin`/`=end` block.

    `strip_ruby_comments` is length-preserving (it overwrites a blanked character with a
    space), so an index comparison IS the "is this inside a comment" test. This guard needs it
    because backtick and `%x{}` literals are not comment-aware in the stripper: the `#` of
    `` `ls #{dir}` `` reads as a comment start, so interpolation has to be matched against the
    RAW line — and then the position check is what keeps a commented-out example silent.
    """
    return idx < len(code) and code[idx] == raw[idx]


class RubyCommandInjectionGuard(Guard):
    id = "ruby-command-injection"
    title = "No OS-command injection via a shell sink (Ruby)"
    area = "Code safety"

    # system("systemctl restart #{service}") -> ruby-command-injection/shell-exec-untrusted.
    canary_plant = CanaryPlant(
        files={
            "deploy.rb": ("def restart(service)\n  system(\"systemctl restart #{service}\")\nend\n"),
        },
        expects=frozenset({"ruby-command-injection/shell-exec-untrusted"}),
    )

    def applies(self, profile: StackProfile) -> bool:
        return "ruby" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []
        seen: set[Path] = set()
        for d in ruby_scan_dirs(root, profile):
            for f in iter_files(d, (".rb",)):
                if f in seen:
                    continue
                seen.add(f)
                # Skip spec/test/fixture trees, exactly as the Python sibling does (#424): a
                # `system("rspec #{file}")` in a Rakefile-style helper or a planted example in
                # a spec is not a product finding.
                if is_nonproduct_path(rel(root, f), profile.archive_segments):
                    continue
                out.extend(self._scan(root, f))
        return out

    def _scan(self, root: Path, f: Path) -> list[Finding]:
        out: list[Finding] = []
        text = read(f)
        # The pragma check reads the COMMENT-ONLY view of the line — it IS the comment `strip_ruby_comments`
        # would blank, and a string quoting it must not count (#424); after stripping it would always miss (the exact ordering bug the
        # sibling `ruby_weak_crypto` guard's adversarial self-test caught before it shipped).
        raw_lines = text.splitlines()
        pragma_lines = pragma_line_set(_PRAGMA, text, dialect="ruby")  # lines whose COMMENT carries it (#424)
        # `strip_ruby_comments` preserves length and splitlines() count exactly, so the two
        # lists always pair up — `strict=True` documents that invariant rather than just
        # quieting the linter.
        code_lines = strip_ruby_comments(text).splitlines()
        for i, (raw, code) in enumerate(zip(raw_lines, code_lines, strict=True), start=1):
            if i in pragma_lines:
                continue
            if self._line_hits(raw, code):
                out.append(self._finding(root, f, i))
        return out

    def _line_hits(self, raw: str, code: str) -> bool:
        for m in _SHELL_SINK.finditer(raw):
            if not _live(raw, code, m.start()):
                continue
            if _is_dynamic(_first_arg(raw[m.end() :])):
                return True
        for m in _BACKTICK.finditer(raw):
            if _live(raw, code, m.start()) and _INTERP.search(m.group(1)):
                return True
        for m in _PERCENT_X.finditer(raw):
            body = next((g for g in m.groups() if g is not None), "")
            if _live(raw, code, m.start()) and _INTERP.search(body):
                return True
        return False

    def _finding(self, root: Path, f: Path, line: int) -> Finding:
        return Finding(
            check_id=self.id,
            severity="critical",
            title="OS command built from untrusted input (Ruby shell sink)",
            location=f"{rel(root, f)}:{line}",
            message=(
                "This Ruby shell call receives an interpolated/concatenated command string — "
                "an attacker who controls that value controls the command (e.g. `; rm -rf /`), "
                "giving remote code execution on the host."
            ),
            remediation=(
                "Use the argv form, which bypasses the shell entirely: "
                '`system("ping", host)` or `system(["ping", host])`, `IO.popen(["ls", dir])`, '
                '`Open3.capture3("git", "clone", url)`. Never build a shell string from '
                "user/model input. If this call is audited-safe, suppress with "
                "`# security: allow-shell-exec`."
            ),
            rule="ruby-command-injection/shell-exec-untrusted",
            standards=["OWASP:A03", "OWASP-LLM:LLM05"],
        )
