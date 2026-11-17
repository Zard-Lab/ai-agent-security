"""Guard: no obfuscated payload decoded then executed (checklist §8, new item).

Malicious agent "skills"/tools and supply-chain-planted backdoors commonly hide their
real behavior behind an encode step so a quick source read (or a naive string-match
scanner) doesn't show the payload in the clear: decode a base64/hex/binary blob, then
hand the result straight to an execution sink. Two independent, high-signal shapes:

  **decode-then-execute chain (HIGH):** a base64/hex/binary decode call
  (`base64.b64decode`, `base64.decodebytes`, `binascii.unhexlify`, `bytes.fromhex`,
  `codecs.decode(..., "hex")`) appears at or shortly before a code/command execution
  sink (`eval`/`exec`, `os.system`/`os.popen`, `subprocess.Popen`/`call`/`run`/
  `check_output`/`check_call`) — whether nested directly (`exec(base64.b64decode(p))`)
  or via a short assign-then-call sequence:

      payload = base64.b64decode(blob)
      exec(payload)                       # decode feeds an exec sink -> fires

  A decode call with no nearby execution sink (e.g. decoding a JWT, a config value, an
  image) does NOT fire — decoding alone is completely ordinary; it's the pairing with
  an execution sink that is the signal.

  **long hex-escape blob (MEDIUM):** a string literal containing 20+ consecutive
  `\\xNN` escapes. Legitimate code essentially never needs a hex blob that long inline
  (binary test fixtures aside, which are excluded via non-product-path skipping) — this
  is the classic shape of an obfuscated shellcode/payload string, independent of
  whether a decode+exec pairing is also visible in the same file.

  **shell decode-then-execute chain (HIGH):** the same pairing principle,
  for the shape a compromised AI-agent "skill" bundle actually ships in: a shell
  `base64 -d` / `--decode` / `openssl base64 -d` / `xxd -r` call CONNECTED to a shell
  interpreter or `eval` sink — either the same physical pipeline (`... | base64 -d | bash`)
  or a captured-then-referenced variable (`p=$(base64 -d <<<$blob); eval "$p"`). Scoped to
  `SKILL.md` and shell scripts, since neither is Python source and the chain rule above
  never sees them — the real-world precedent is a reverse shell redistributed through a
  public skill registry, and a reverted PR that bundled an obfuscated script inside a
  `.claude`-shaped skill file. Connectedness, not mere proximity, is required: a bare
  window check (decode anywhere within N lines of a sink) fired on a markdown command
  table's own unrelated rows and on ordinary devops scripts that decode a cert on one line
  and pipe an unrelated command to a shell a few lines later — the same FP class
  `claude-code-compromise`'s mkfifo pairing already documents at length for a sibling rule
  (see that guard's own connectedness rationale). Scanned regardless of `.gitignore`
  (`.claude/` is commonly gitignored — a skill pulled from a public registry into a
  gitignored tree must not silently disappear from this scan).

  **JS-side decoded/self-decoding eval (HIGH, 2026-10-07):** a base64/char-code-decoded
  blob or a self-decoding function expression passed straight to `eval`/`new Function`
  `eval(atob(blob))`, `eval(function(){...})()`, `eval(decoder([99,111,...]))`. The
  JS-side counterpart of the Python decode-exec-chain above, adapted from Datadog
  GuardDog's `threat-runtime-obfuscation-dynamic-eval` source-code rule. Legitimate
  code defines and calls named functions; it does not eval a decoded blob or a
  function expression.

Fires on Python source when `python` is detected, on JS/TS source when `javascript`/
`typescript` is detected, plus (for the shell chain rule only) `SKILL.md` and shell
scripts anywhere in the repo, regardless of stack. Suppress an audited case with:

    exec(base64.b64decode(trusted_constant))  # security: allow-obfuscated-payload-execution

In a `SKILL.md` specifically, `#`-prefixed text renders as a literal heading rather than a
comment, so the HTML-comment form also works there (shell scripts still use the `#` form):

    <!-- security: allow-obfuscated-payload-execution -->
"""
from __future__ import annotations

import re
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import (
    CanaryPlant,
    Guard,
    comment_dialect_for,
    is_nonproduct_path,
    iter_files,
    iter_files_named,
    pragma_line_set,
    pragma_present,
    python_scan_dirs,
    read,
    rel,
    strip_js_comments,
    strip_python_strings,
)

_DECODE = re.compile(
    r"\b(?:base64\.(?:b64decode|decodebytes|b32decode|b85decode|urlsafe_b64decode)|"
    r"binascii\.unhexlify|bytes\.fromhex|codecs\.decode)\s*\("
)
_EXEC_SINK = re.compile(
    r"(?<!\.)\b(?:eval|exec)\s*\(|\bos\.(?:system|popen)\s*\(|"
    r"\bsubprocess\.(?:Popen|call|run|check_output|check_call)\s*\("
)
_HEX_BLOB = re.compile(r"(?:\\x[0-9a-fA-F]{2}){20,}")
_PRAGMA = re.compile(r"#\s*security:\s*allow-obfuscated-payload-execution")
# `#`-prefixed text renders as a literal H1 heading (or literal table-cell text) in
# rendered markdown — the one syntax invisible in rendered output doesn't work as an opt-out in
# a SKILL.md. `<!-- -->` does. Scoped to `.md` files only (`_scan_skill_shell`'s use, below) — NOT
# widened for `.py`/`.sh`, where `#` is the real comment character and an HTML-comment opt-out
# would be meaningless noise there.
_PRAGMA_MD = re.compile(
    r"#\s*security:\s*allow-obfuscated-payload-execution"
    r"|<!--\s*security:\s*allow-obfuscated-payload-execution\s*-->"
)

# How many lines back from an execution sink to look for a preceding decode call.
_WINDOW = 5

_CHAIN_STANDARDS = ["OWASP:A03", "CWE-506"]
_HEX_STANDARDS = ["OWASP:A03", "CWE-506"]

# ── shell decode-then-execute chain (agent-skill bundle blind spot) ────────────────
_SHELL_DECODE = re.compile(
    r"\bbase64\s+(?:-d\b|--decode\b)|\bopenssl\s+base64\s+-d\b|\bxxd\s+-r\b",
    re.IGNORECASE,
)
# A pipe into a shell interpreter or eval — the moment the decoded blob is handed over for
# execution. Deliberately narrow (pipe-to-shell / eval only) to keep this low-FP: `base64 -d`
# alone (decoding a cert, a JSON payload, a config value to a file) is completely ordinary and
# must not fire — it's the pairing with an execution sink that is the signal, same as the
# Python chain rule above.
_SHELL_EXEC_SINK = re.compile(
    r"\|\s*(?:sudo\s+)?(?:env\s+\S+\s+)?(?:ba|z|k)?sh\b|"
    r"\|\s*eval\b|\beval\s+[\"'$]|\bsource\s+/dev/stdin\b",
    re.IGNORECASE,
)
_SKILL_SHELL_GLOBS = ("SKILL.md", "*.sh", "*.bash", "*.zsh")
_SKILL_WINDOW = 3
_SKILL_SHELL_STANDARDS = ["OWASP:A03", "CWE-506"]
# A decode call captured into a shell variable — `VAR=$(...)` or `` VAR=`...` `` — so a later
# line referencing `$VAR`/`${VAR}` as its sink operand is provably fed by that decode, not just
# nearby. Mirrors `_FD_BIND`/`_VAR_BIND` in claude_code_compromise.py (same connectedness
# principle, different transport).
#
# The optional quote after `=` is load-bearing, not cosmetic: `VAR="$(...)"` is the form ShellCheck
# pushes you toward (SC2046/SC2086) and is at least as common in real scripts as the bare form. The
# first cut of this pattern required `$(` immediately after `=`, which meant the connectedness
# narrowing silently DROPPED a chain the previous proximity check had caught — a real detection lost
# to an FP fix, which is the exact trade CLAUDE.md rule 1 exists to catch (#606 review round 2, H2).
# Measured: restoring the quote recovers `VAR="$(...)"`, ``VAR="`...`"`` and `export VAR="$(...)"`
# while every FP fixture from the H1 round stays silent.
_VAR_DECODE_ASSIGN = re.compile(r"""\b([A-Za-z_]\w*)=\s*["']?(\$\([^()\n]*\)|`[^`\n]*`)""")

# ── JS-side obfuscated-eval execution (2026-10-07, Datadog GuardDog research-cycle) ──────────
# `obfuscated-payload-execution` was Python-only by design (the hex-blob/decode-exec-chain
# rules above are Python-specific). This is the JS-side counterpart to the SAME underlying
# threat shape (a decoded/self-decoding payload fed straight to a dynamic-execution sink),
# adapted from Datadog GuardDog's `threat-runtime-obfuscation-dynamic-eval` source-code rule.
# High specificity per that source's own metadata: legitimate code defines and calls named
# functions, it does not eval a function *expression*, and it does not base64/char-code-decode
# a blob only to immediately eval/Function it.
_JS_EVAL_FUNC_EXPR = re.compile(r"\beval\s*\(\s*function\s*\(", re.IGNORECASE)
_JS_EVAL_ATOB = re.compile(r"\beval\s*\(\s*atob\s*\(|\bnew\s+Function\s*\(\s*atob\s*\(", re.IGNORECASE)
_JS_EVAL_FROMCHARCODE = re.compile(
    r"\beval\s*\([^;]{0,160}\bfromCharCode\b|\bnew\s+Function\s*\([^;]{0,160}\bfromCharCode\b",
    re.IGNORECASE,
)
_JS_EVAL_DECODER_ARRAY = re.compile(
    r"\beval\s*\(\s*[A-Za-z_$][\w$]*\s*\(\s*\[\s*\d{1,3}(\s*,\s*\d{1,3}){19,}", re.IGNORECASE
)
_JS_SUFFIXES = (".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs")
_JS_STANDARDS = ["OWASP:A03", "CWE-506"]
_PRAGMA_JS = "security: allow-obfuscated-payload-execution"


class ObfuscatedPayloadExecutionGuard(Guard):
    id = "obfuscated-payload-execution"
    title = "No obfuscated payload (base64/hex/binary-decoded) fed to an execution sink"
    area = "Code safety"

    # SKILL.md: a same-line `base64 -d | bash` pipeline -> fires
    # obfuscated-payload-execution/skill-shell-decode-exec-chain (HIGH). Same-line connected
    # (decode and sink on one physical pipeline), not just proximity — the guard requires
    # connectedness (H1 fix), so a plant must actually be connected to prove the
    # rule still discriminates real chains from mere nearby mentions.
    # payload_decoder.py: base64.b64decode(blob) then exec(payload) -> decode-exec-chain
    # (HIGH); MAGIC = "\x90"*25 -> hex-blob-literal (MEDIUM).
    canary_plant = CanaryPlant(
        files={
            "SKILL.md": (
                "---\nname: canary-skill\n---\n"
                "echo \"$PAYLOAD\" | base64 -d | bash\n"
            ),
            "canary-obfuscated-eval.js": "eval(atob('Y29uc29sZS5sb2coMSk7'));\n",
        },
        expects=frozenset({
            "obfuscated-payload-execution/decode-exec-chain",
            "obfuscated-payload-execution/hex-blob-literal",
            "obfuscated-payload-execution/skill-shell-decode-exec-chain",
            "obfuscated-payload-execution/js-decoded-eval",
        }),
    )

    def applies(self, profile: StackProfile) -> bool:  # noqa: ARG002
        # Unconditional (like claude-code-compromise): an AI-agent skill bundle can carry a
        # shell decode-exec chain regardless of the target repo's detected stack.
        return True

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []
        # Gated on the python feature (restores pre-widening scope): applies() went
        # unconditional only to let the skill/shell scan below run stack-agnostically, not to
        # make the Python decode-exec-chain/hex-blob-literal rules run on every repo (a repo
        # with no python feature and a stray .py file must not gain new findings from this).
        if "python" in profile.features:
            seen: set[Path] = set()
            for d in python_scan_dirs(root, profile):
                for f in iter_files(d, (".py",)):
                    if f in seen:
                        continue
                    seen.add(f)
                    if is_nonproduct_path(rel(root, f), profile.archive_segments):
                        continue
                    out.extend(self._scan(root, f))
        if {"javascript", "typescript"} & profile.features:
            seen_js: set[Path] = set()
            for f in iter_files(root, _JS_SUFFIXES):
                if f in seen_js:
                    continue
                seen_js.add(f)
                if is_nonproduct_path(rel(root, f), profile.archive_segments):
                    continue
                out.extend(self._scan_js(root, f))
        out.extend(self._scan_skill_shell(root, profile))
        return out

    def _scan_js(self, root: Path, f: Path) -> list[Finding]:
        text = read(f)
        if pragma_present(_PRAGMA_JS, text, dialect="js"):
            return []
        code = strip_js_comments(text, strip_strings=False)
        for i, line in enumerate(code.splitlines(), start=1):
            if (
                _JS_EVAL_FUNC_EXPR.search(line)
                or _JS_EVAL_ATOB.search(line)
                or _JS_EVAL_FROMCHARCODE.search(line)
                or _JS_EVAL_DECODER_ARRAY.search(line)
            ):
                return [self._js_finding(root, f, i)]
        return []

    def _js_finding(self, root: Path, f: Path, line: int) -> Finding:
        return Finding(
            check_id=self.id,
            severity="high",
            title=self.title,
            location=f"{rel(root, f)}:{line}",
            message=(
                "A base64/char-code-decoded or self-decoding function expression is passed "
                "directly to `eval`/`new Function`: the JS-side counterpart of a "
                "decode-then-execute chain. Legitimate code defines and calls named functions; "
                "it does not eval a decoded blob or a function expression."
            ),
            remediation=(
                "Never decode-then-execute a runtime-supplied or bundled blob in JS either. "
                "If the decoded content really is code that must run, keep it in a reviewable, "
                "static source file instead of an encoded/self-decoding expression."
            ),
            rule="obfuscated-payload-execution/js-decoded-eval",
            standards=list(_JS_STANDARDS),
        )

    def _scan(self, root: Path, f: Path) -> list[Finding]:
        out: list[Finding] = []
        text = strip_python_strings(read(f), filename=f)
        lines = text.splitlines()
        # Both rules honour the pragma only as a real comment, never quoted in a string (#1040),
        # numbered on these lines (a form feed in a docstring shifts the raw count, #1132). The set
        # is 1-based, the first loop 0-based.
        pragmas = pragma_line_set(_PRAGMA, text, dialect="python")

        for i, line in enumerate(lines):
            if i + 1 in pragmas:
                continue
            stripped = line.lstrip()
            if stripped.startswith("#"):
                continue
            if not _EXEC_SINK.search(line):
                continue
            first = max(0, i - _WINDOW)
            window = lines[first:i + 1]
            if any(_DECODE.search(w) for w in window) and not any(
                n in pragmas for n in range(first + 1, i + 2)
            ):
                out.append(self._chain_finding(root, f, i + 1))

        for i, line in enumerate(lines, start=1):
            if line.lstrip().startswith("#") or i in pragmas:
                continue
            if _HEX_BLOB.search(line):
                out.append(self._hex_finding(root, f, i))

        return out

    def _chain_finding(self, root: Path, f: Path, line: int) -> Finding:
        return Finding(
            check_id=self.id,
            severity="high",
            title=self.title,
            location=f"{rel(root, f)}:{line}",
            message=(
                "A base64/hex/binary decode call feeds an execution sink (eval/exec, "
                "os.system/popen, or subprocess) within a few lines. Decoding-then-executing "
                "is the classic shape of an obfuscated malicious payload hiding from a "
                "plain-text source read."
            ),
            remediation=(
                "Never decode-then-execute a runtime-supplied or bundled blob. If the "
                "decoded content really is code that must run, keep it in a reviewable, "
                "static source file instead of an encoded string."
            ),
            rule="obfuscated-payload-execution/decode-exec-chain",
            standards=list(_CHAIN_STANDARDS),
        )

    def _scan_skill_shell(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []
        # respect_gitignore=False: .claude/ (where a real skill bundle lives) is routinely
        # gitignored, and a silent zero-findings result on a gitignored skill tree is worse
        # than the noise of scanning it — CLAUDE.md rule 3 (a clean-looking miss is the worst
        # failure shape). claude_code_compromise.py's CODEX_HOME rule already opts out the
        # same way for the same reason.
        for f in iter_files_named(root, *_SKILL_SHELL_GLOBS, respect_gitignore=False):
            r = rel(root, f)
            if is_nonproduct_path(r, profile.archive_segments):
                continue
            # SKILL.md is markdown (renders `#`-prefixed text as a literal heading, not a
            # comment); .sh/.bash/.zsh keep `#` as the real comment character. Only the .md
            # case also accepts `<!-- -->`.
            pragma = _PRAGMA_MD if f.suffix.lower() == ".md" else _PRAGMA
            text = read(f)
            # A shell script's pragma counts only as a real `#` comment, never quoted in a string
            # (#1040). SKILL.md has no comment dialect, so `comment_dialect_for` gives None and its
            # lines stay raw, as for every Markdown guard (#1040 T5): `<!-- -->` there is HTML,
            # not a grammar any view reads. The set is 1-based, the loops 0-based.
            pragmas = pragma_line_set(pragma, text, dialect=comment_dialect_for(f))
            lines = text.splitlines()
            for i, line in enumerate(lines):
                if i + 1 in pragmas:
                    continue
                if not _SHELL_EXEC_SINK.search(line):
                    continue
                # Connectedness, not proximity: same physical line (a real pipeline), or a
                # variable captured from a decode on an earlier line and referenced by this
                # sink line. A decode merely PRESENT somewhere in the backward window is not
                # enough — see the module docstring's connectedness note.
                connected = _SHELL_DECODE.search(line) is not None
                if not connected:
                    start = max(0, i - _SKILL_WINDOW)
                    for k, decode_line in enumerate(lines[start:i], start=start + 1):
                        if k in pragmas:
                            continue
                        if self._var_alias_connected(decode_line, line):
                            connected = True
                            break
                if connected:
                    out.append(self._skill_shell_finding(root, f, i + 1))
                    break  # one finding per file, matching claude_code_compromise.py's rules
        return out

    def _var_alias_connected(self, decode_line: str, sink_line: str) -> bool:
        """True if *decode_line* binds a shell variable to a decode call (`VAR=$(...)` or
        `` VAR=`...` ``) AND *sink_line* references that same variable (`$VAR`/`${VAR}`) —
        the two-line form of the connectedness requirement (see `_scan_skill_shell`)."""
        m = _VAR_DECODE_ASSIGN.search(decode_line)
        if not m or not _SHELL_DECODE.search(m.group(2)):
            return False
        var = m.group(1)
        return re.search(rf"\$\{{?{re.escape(var)}\}}?\b", sink_line) is not None

    def _skill_shell_finding(self, root: Path, f: Path, line: int) -> Finding:
        return Finding(
            check_id=self.id,
            severity="high",
            title=self.title,
            location=f"{rel(root, f)}:{line}",
            message=(
                "An AI-agent skill file or script decodes a base64/hex blob and pipes it "
                "straight into a shell interpreter or `eval`. Skill/instruction bundles are "
                "fetched and run with the same trust as hand-written scripts, so a "
                "decode-then-execute chain hidden inside one is the same obfuscated-payload "
                "shape as malicious source code — a real-world incident redistributed a "
                "reverse shell this way through a public skill registry."
            ),
            remediation=(
                "Never decode-then-execute a bundled or fetched blob inside a skill file or "
                "script. If a skill genuinely needs to run code, ship it in the clear as a "
                "reviewable file instead of an encoded blob piped to a shell."
            ),
            rule="obfuscated-payload-execution/skill-shell-decode-exec-chain",
            standards=list(_SKILL_SHELL_STANDARDS),
        )

    def _hex_finding(self, root: Path, f: Path, line: int) -> Finding:
        return Finding(
            check_id=self.id,
            severity="medium",
            title=self.title,
            location=f"{rel(root, f)}:{line}",
            message=(
                "A string literal contains a long run (20+) of consecutive `\\xNN` hex "
                "escapes. Application code essentially never needs an inline hex blob this "
                "long — this is the classic shape of an obfuscated shellcode/payload string."
            ),
            remediation=(
                "Move genuinely necessary binary data to a checked-in binary fixture/asset "
                "file, not an inline hex-escaped string literal in source."
            ),
            rule="obfuscated-payload-execution/hex-blob-literal",
            standards=list(_HEX_STANDARDS),
        )
