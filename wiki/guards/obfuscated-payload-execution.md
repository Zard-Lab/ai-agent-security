---
type: Guard
title: "obfuscated-payload-execution"
description: "No obfuscated payload (base64/hex/binary-decoded) fed to an execution sink."
timestamp: "2026-07-12T21:10:55+08:00"
guard_id: "obfuscated-payload-execution"
checklist_section: ["8"]
standards: ["OWASP:A03"]
---

# No obfuscated payload (base64/hex/binary-decoded) fed to an execution sink

_Author — 2026-07-12_

---

## The threat

A malicious agent "skill"/tool package, a supply-chain-planted backdoor, or an
attacker-modified dependency hides its real behavior behind an encode step so a
plain source read (or a naive string-match scanner) never shows the payload in the
clear: decode a base64/hex/binary blob at runtime, then hand the decoded bytes
straight to `eval`/`exec`/`os.system`/`subprocess`. Anyone who can get this code
merged or loaded (a compromised dependency, a malicious agent-skill file scanned by
tools like cisco-ai-defense/skill-scanner, an insider) gets arbitrary code execution
that a plain-text `grep` for suspicious calls will not surface, because the actual
command/code string never appears as a literal. OWASP:A03 (Injection), CWE-506
(Embedded Malicious Code).

## Why it's often introduced / Why this guard fits the stack

The pattern shows up in exactly the kind of "agent tool"/"skill" code this stack
increasingly loads dynamically — a downloaded tool bundle that does:

```python
import base64
payload = base64.b64decode(config["init_blob"])
exec(payload)
```

or a dependency's `setup.py`/post-install hook that decodes then runs a shell
command. It also shows up as accidental self-obfuscation (a developer base64-encoding
a script to dodge line-length or escaping issues), which is exactly why this guard
only fires on the *decode-then-execute* shape, not decoding alone.

## Detection design

1. **`applies()` gate** — `"python" in profile.features` (mirrors
   `code-injection-eval-exec`, the nearest sibling).
2. **Files scanned** — `.py` files under `python_scan_dirs(root, profile)`, via
   `iter_files`; non-product paths (`tests/`, fixtures, migrations) skipped via
   `is_nonproduct_path`.
3. **Patterns / logic** — two independent rules:
   - `decode-exec-chain`: a decode call (`base64.b64decode`/`decodebytes`/
     `b32decode`/`b85decode`/`urlsafe_b64decode`, `binascii.unhexlify`,
     `bytes.fromhex`, `codecs.decode`) found on the same line as, or within the
     preceding 5 lines of, an execution sink (`eval`/`exec`, `os.system`/`os.popen`,
     `subprocess.Popen`/`call`/`run`/`check_output`/`check_call`). A 5-line
     backward-only window models the realistic "decode, then execute" order and
     keeps the match tight enough to avoid coincidental co-occurrence.
   - `hex-blob-literal`: a string literal containing 20+ consecutive `\xNN` escapes
     on a single physical line — a standalone signal independent of any visible
     exec pairing (the decode/exec may happen through indirection elsewhere).
4. **Pragma** — `# security: allow-obfuscated-payload-execution` as a real `#` comment,
   checked on the sink/window lines for the chain rule and on the literal's own line for the hex
   rule; the phrase quoted in a string on those lines does not count (#1040). The JS rule (below) checks the same phrase as a `//` comment anywhere in the
   file via `pragma_present(..., dialect="js")`.
5. **Severity / rule ids** — `decode-exec-chain` is HIGH
   (`obfuscated-payload-execution/decode-exec-chain`, `OWASP:A03`); `hex-blob-literal`
   is MEDIUM (`obfuscated-payload-execution/hex-blob-literal`, `OWASP:A03`) — lower
   because a long hex literal alone is suspicious but not proven to reach execution.
6. **JS-side decoded/self-decoding eval (2026-10-07, extension):** gated on
   `"javascript"`/`"typescript"` in `profile.features`. Scans `.js`/`.ts`/`.jsx`/
   `.tsx`/`.mjs`/`.cjs`, comment-stripped via `strip_js_comments`. Fires on
   `eval(function(...)` (a self-invoking packed/self-decoding wrapper), `eval(atob(`/
   `new Function(atob(`, `eval`/`new Function` over a `fromCharCode` decode, or
   `eval` of a decoder call applied to a 20+ element numeric (char-code) array.
   Adapted from Datadog GuardDog's `threat-runtime-obfuscation-dynamic-eval` rule.
   `severity="high"`, rule `obfuscated-payload-execution/js-decoded-eval`,
   `OWASP:A03`/`CWE-506`. Each primitive alone is ordinary and stays silent (`atob(s)`,
   `new Function('a','return a')`, `String.fromCharCode(65)`, `eval('1+1')`, a numeric
   array passed to a non-eval call, or an `eval` and a `fromCharCode` in separate
   `;`-statements); only the pairing fires. A packer-wrapped vendored bundle
   (`eval(function(p,a,c,k,e,d){...})` in a committed `*.min.js` outside `node_modules/`/
   `dist/`) does fire, by design: that is obfuscated code run through `eval`, so a reviewed
   one takes the pragma or an exception.

## When NOT to flag

- A decode call with no execution sink anywhere nearby (JWT segment decoding, a
  config value, an image/file blob) — completely ordinary, does not fire.
- An execution sink with no decode call nearby (`subprocess.run(cmd_parts)` on a
  plain list) — does not fire; this guard is not a general command-injection check
  (see `command-injection` for that).
- A short hex-escape run (under 20) — normal binary literals (a single opcode, a
  short magic-bytes check) stay silent.

## Tests

| Test | What it checks |
|---|---|
| `test_fires_on_nested_decode_exec` | `exec(base64.b64decode(blob))` on one line fires the chain rule, HIGH |
| `test_fires_on_assign_then_exec` | decode assigned to a variable, `exec()`'d two lines later, fires |
| `test_fires_on_hex_unhexlify_then_subprocess` | `binascii.unhexlify` feeding `subprocess.run(..., shell=True)` fires |
| `test_passes_decode_with_no_nearby_exec` | a JWT-style decode with no execution sink anywhere near stays silent |
| `test_passes_exec_with_no_nearby_decode` | `subprocess.run(cmd_parts)` with no decode call stays silent |
| `test_decode_beyond_window_does_not_fire` | a decode call more than 5 lines before an unrelated `exec()` stays silent |
| `test_pragma_opt_out_chain` | the pragma on the exec line silences the chain rule |
| `test_fires_on_long_hex_blob_literal` | 25 consecutive `\xNN` escapes on one line fires the hex rule, MEDIUM |
| `test_passes_short_hex_run` | 5 consecutive `\xNN` escapes stays silent |
| `test_pragma_opt_out_hex_blob` | the pragma on the literal's line silences the hex rule |
| `test_passes_docstring_example` | an anti-pattern example inside a docstring does not self-fire |
| `test_fires_on_js_eval_atob` | `eval(atob(blob))` fires the JS rule, HIGH |
| `test_fires_on_js_eval_self_decoding_function_expression` | `eval(function(p,a,c,k,e,d){...}(...))` packer-style self-decode fires |
| `test_js_rule_does_not_fire_without_js_feature` | the JS rule stays silent with no javascript/typescript feature |
| `test_js_passes_ordinary_named_function_call` | an ordinary named-function call stays silent |
| `test_js_passes_benign_decode_function_and_eval_uses` | `atob`, `new Function`, `fromCharCode`, `eval('1+1')`, a 20-element numeric array, each on its own or split by `;`, stay silent (mutation-proven to reach every JS regex) |
| `test_js_pragma_suppresses` | a `//` pragma comment silences the JS rule |

## Known bypasses

- Splitting the decode and exec across more than 5 lines, or routing the decoded
  value through an intermediate function call before executing it, evades the
  window-based chain check entirely.
- Using a decode primitive not in the fixed list (e.g. a custom XOR/rot13 routine,
  `zlib.decompress`, a manually written base64 alphabet table) evades both rules.
- Splitting a long hex blob across multiple adjacent string literals (implicit
  concatenation) evades the hex rule, since it matches per physical line.
- Building the encoded blob at runtime (fetched from a URL, read from a file) rather
  than as an inline literal evades the hex rule; the chain rule would still catch the
  execution side if a decode call is present nearby.

## What this guard does NOT prove

A silent result does not mean the file is free of obfuscated/malicious code — it
only means no *decode call textually near an execution sink* and no *long inline hex
literal* were found. It cannot detect obfuscation via other encodings, dynamic
decode-function resolution (`getattr(base64, method_name)`), payloads assembled at
runtime from network/file sources, or malicious behavior that needs no decoding step
at all (a plainly readable but malicious import, for instance — out of scope here;
see `code-injection-eval-exec` and `command-injection` for the broader sink checks).

---

## 2026-08-14 — shell decode-exec chain (SKILL.md / shell scripts)

**Gap:** this guard's own threat model (§1 above) explicitly names "a malicious agent-skill file"
as a motivating case, but `applies()` gated on `"python" in profile.features` and `run()` only ever
scanned `.py` files — an actual skill bundle (`SKILL.md` plus shell scripts, not Python) was never
scanned. The concrete precedent: a reverse shell redistributed through a public skill registry, and
a reverted PR bundling an obfuscated script inside a `.claude`-shaped skill file — both are shell-side
decode-then-execute, invisible to the Python-only chain rule.

**Fix — new rule `skill-shell-decode-exec-chain` (HIGH):**
1. **`applies()` widened** to unconditional `True` (was python-only) — a poisoned skill file isn't
   stack-gated, same reasoning as `claude-code-compromise`.
2. **Files scanned** — `SKILL.md` + `*.sh`/`*.bash`/`*.zsh`, repo-wide via `iter_files_named`
   (mirrors `claude-code-compromise`'s broad script scan).
3. **Pattern** — same decode-near-exec-sink pairing principle as the Python rule, translated to
   shell syntax: `_SHELL_DECODE` (`base64 -d`/`--decode`, `openssl base64 -d`, `xxd -r`) within a
   3-line backward window of `_SHELL_EXEC_SINK` (a pipe into `sh`/`bash`/`zsh`/`ksh`, a pipe into
   `eval`, `eval "..."`, or `source /dev/stdin`). Deliberately narrow to the execution-sink pairing,
   not the decode call alone — `base64 -d` decoding a cert or config to a file is completely
   ordinary and must stay silent (mirrors the Python rule's own FP-avoidance rationale).
4. **Pragma** — same `# security: allow-obfuscated-payload-execution`, checked on the window lines.
   In a shell script it counts only as a real `#` comment, never quoted in a string (#1040). A
   SKILL.md has no comment grammar a view reads, so its lines are still matched raw, `<!-- -->`
   form included.
5. **Severity / rule id** — `obfuscated-payload-execution/skill-shell-decode-exec-chain`, HIGH,
   `OWASP:A03`/`CWE-506` (same standards as the Python chain rule).

**Tests added:** `test_applies_unconditionally`, `test_fires_on_skill_md_base64_piped_to_bash`,
`test_fires_on_shell_script_base64_piped_to_eval`, `test_passes_base64_decode_with_no_shell_sink`
(FP-bait: decode-to-file, no shell sink), `test_skill_shell_pragma_opt_out`,
`test_skill_shell_not_scanned_outside_skill_or_script_files` (FP-bait: a README documenting the
same one-liner as prose must not fire).

**Known bypass (same class as the Python rule):** splitting the decode and the shell sink across
more than 3 lines evades the window check even when genuinely connected (the variable-alias fix
below only bridges a decode captured on one line to a sink referencing it on a later line within
the window — it does not chase indirection through an intermediate function or a third
variable-to-variable hop). A **Python** decode-exec chain fenced inside a `SKILL.md` code block
(` ```python\nexec(base64.b64decode(...))\n``` `) is invisible to both this rule (wrong pattern
shape — shell syntax, not Python) and the Python chain rule above (wrong file suffix — only `.py`
files are fed to `_scan`); closing that is a separate PR, not scoped here.

**Scope note:** MCP tool-definition JSON was considered for this same pass and found already
well-covered — `mcp-config-security`'s `dangerous-exec-command` rule already catches a `command`
field resolving to a shell wrapper with a payload marker, and `mcp-tool-description-injection`
already checks for unscanned tool-description content. No gap found there; this pass is scoped to
the `SKILL.md` blind spot only.

---

## 2026-08-16 — fix round answering an agentic pre-review: connectedness, gitignore, and 3 more gaps

The pre-review (2 High, 5 Medium, 3 Low) was independently re-verified by direct execution before
any fix was written (every claim below reproduced first, not taken on the review's report), per
this project's diagnosis-vs-prescription discipline.

**H1 — the rule paired on proximity alone, the exact FP class `claude-code-compromise`'s mkfifo
rule already documents and closed once (#450).** Reproduced all 6 of the review's measured false
positives (`install.sh`/`bootstrap.sh`/`wrapper.sh`-style unrelated statements a few lines apart,
plus 2 markdown-table shapes whose own `|` cell delimiters coincidentally satisfy the sink
pattern). **Fix:** replaced the window-presence check with a connectedness requirement — either
the decode and the sink share the same physical line (a real pipeline: `... | base64 -d | bash`),
or the decode is captured into a shell variable (`VAR=$(...)`/`` VAR=`...` ``) that a later sink
line within the window references by name (`_var_alias_connected`, mirroring
`claude_code_compromise.py`'s `_FD_BIND`/`_VAR_BIND` alias-tracking for the same connectedness
principle over a different transport). Deliberately did NOT strip markdown fences before matching
— the review measured that this creates a false negative on a fenced `| base64 -d | bash`, the
likeliest real shape of a poisoned skill, so a fenced "NEVER do this" anti-example is a known,
accepted residual FP (pinned by `test_skill_shell_fires_on_fenced_doc_example`) rather than risk
that FN.

**H2 — the scan was silently void on any repo that gitignores `.claude/`.** Reproduced: 0
findings on a gitignored `.claude/skills/evil/SKILL.md` carrying an unambiguous chain, vs. 1
finding when not gitignored — exit 0, no disclosure, indistinguishable from "no skills present."
**Fix:** `iter_files_named(..., respect_gitignore=False)` for the skill/shell scan, matching the
in-file precedent `claude_code_compromise.py`'s CODEX_HOME rule already sets for the same reason.

**M2 — checklist drift.** `applies_when` still said `["python"]` after `applies()` went
unconditional, so `agentsec coverage` reported this item `n/a` on repos where the guard was in
fact running and could fire HIGH. **Fix:** `applies_when: []`, matching `claude-code-compromise`'s
own unconditional-applies items in the same checklist.

**M3 — a second, undisclosed widening.** `applies()` going unconditional also let the pre-existing
Python `decode-exec-chain`/`hex-blob-literal` rules run on repos with no `python` feature detected
(`python_scan_dirs()` falls back to the repo root with no `python_dirs`). Reproduced: a bare repo
with one stray `.py` file containing `exec(base64.b64decode(blob))` went from 0 findings to 1
under the PR as shipped. **Fix:** re-gated the Python-file loop in `run()` on
`"python" in profile.features` explicitly — restores the pre-PR Python scope while keeping the
skill/shell scan unconditional, which is the only widening this PR's own stated rationale
justifies.

**M4 — no per-file cap.** A single `SKILL.md` with 2 genuinely connected chains produced 2
separate findings, unlike every rule in the sibling guard, all of which cap at one finding per
file. **Fix:** `break` after the first connected hit per file.

**M5 — no canary coverage for the new rule.** `agentsec/canary.py`'s `expects` for this guard
still named only `{decode-exec-chain, hex-blob-literal}`; a `SKILL.md` plant (a same-line
connected `echo "$PAYLOAD" | base64 -d | bash`) was added to `_BASE_FILES` and
`skill-shell-decode-exec-chain` added to `expects`. Confirmed it doesn't create a new self-audit
finding: the shell scan targets files by NAME (`SKILL.md`/`*.sh`/…), and `canary.py` isn't named
that, so the string literal inside it is never fed to `_scan_skill_shell` — verified by running
`agentsec audit .` and confirming the only self-match is the pre-existing `canary.py:2184`
Python-side plant, unchanged from before this fix round.

**M1 — the existing FP-bait test's own annotation overstated what it proves.**
`test_skill_shell_not_scanned_outside_skill_or_script_files` was commented as "a README documenting
the same one-liner as prose must not fire," which reads as prose-tolerance; it actually proves only
file-name scoping (put the identical text in a `SKILL.md` and it fires). Comment corrected; the
gap it left — no test for the benign neighbour "a SKILL.md *discussing* a chain, not containing a
connected one" — is now covered by the markdown-table and fenced-doc-example tests added for H1.

**Deferred, not fixed here (Lows, matches the review's own "follow-up, not a blocker" framing):**
L1 (accept `<!--` HTML-comment pragma syntax for markdown files — the `#`-only form renders as a
literal heading in a `SKILL.md`) and L2 (`ai_instruction_poisoning.py` still doesn't scan
`SKILL.md`, so the AI-instruction-file list is now inconsistent across 3 guards). Both left as
follow-up work rather than folded into an already-large fix round; L3 (the Python-in-SKILL.md-fence
gap) is documented above in the "Known bypass" note since it's a one-line doc addition.

**Tests added this round:** `test_skill_shell_silent_on_unrelated_shell_statements_in_proximity`,
`test_skill_shell_silent_on_markdown_table_rows`, `test_skill_shell_fires_on_fenced_doc_example`,
`test_skill_shell_scans_gitignored_skill_tree`, `test_skill_shell_one_finding_per_file`,
`test_decode_exec_chain_silent_without_python_feature`,
`test_decode_exec_chain_fires_with_python_feature`.

# Citations

[1] agentsec checklist item `8-obfuscated-payload-execution` (§8)
[2] OWASP:A03
