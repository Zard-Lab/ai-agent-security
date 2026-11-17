---
type: Research
title: Cisco Skill Scanner — Agentic Security Patterns
description: Statically-detectable malicious-file and persistence patterns distilled from cisco-ai-defense/skill-scanner's threat taxonomy for AI agent skill bundles, mapped to agentsec coverage.
tags: [research, agentic, skills, malicious-file, supply-chain, obfuscation]
timestamp: "2026-07-12T00:00:00Z"
---

# Cisco Skill Scanner — Agentic Security Patterns

## What this covers

[`cisco-ai-defense/skill-scanner`](https://github.com/cisco-ai-defense/skill-scanner)
is Cisco's scanner for AI agent "skill" bundles (Claude Code Skills-shaped
directories) — a static YAML+YARA threat taxonomy plus a behavioral/dataflow
analysis layer. The patterns below describe the *concepts* its static taxonomy
checks for, in our own words (the repo's license is a custom "Other" variant, so no
rule text is reproduced verbatim) — mapped to what a general-purpose static guard
can detect independent of any skill-bundle-specific file structure.

Same problem space as SkillSpector (see [SkillSpector patterns](skillspector-patterns.md)
in an earlier research pass) — expected overlap, but this source's strongest
original contribution was the *malicious-file-format* angle: threats that live in
the file itself (an SVG, a PDF) rather than in ordinary source code.

## Malicious content hiding inside a "just a file" upload

Two file formats are commonly accepted as inert documents/assets but the format
itself permits embedded, auto-executing behavior:

| Pattern | Format-level capability | Detection |
|---|---|---|
| SVG script/event-handler/URI | SVG is XML; the spec permits `<script>`, `on<event>=` handlers, and `javascript:` URIs — a browser rendering the SVG inline executes them | A `.svg` file containing any of the three literal markers |
| PDF embedded JavaScript / auto-run | PDF readers execute `/JS`/`/JavaScript` actions by default; `/OpenAction` triggers on open; `/Launch` runs an external program | A `.pdf` file containing any of the three literal markers, scanned as raw text (these keys live in never-compressed object dictionaries) |

Both are content-format checks, not code-pattern checks — a static line-matching
regex over Python/JS source can't see this class of finding at all, since the
"vulnerable code" lives inside a binary/markup asset, not a script.

## Persistence via a dot-prefixed executable

A file whose name starts with `.` is hidden from a plain directory listing — an
attacker (or a malicious skill's install step) naming a planted script `.update.sh`
or `.cache.py` blends it into a listing full of legitimate dotfiles (`.env`,
`.gitignore`, `.eslintrc`). The detectable signal is filename-only: a leading dot
plus a script-executable extension. The scoping decision worth stating plainly: `.js`/
`.ts` extensions are excluded from this check, because hidden JS/TS config files
(`.eslintrc.js`, `.babelrc.js`, `.prettierrc.js`, and similar) are an extremely
common, entirely legitimate tooling convention — including them would make the
check mostly noise on any real JS/TS repo. `.py`/`.sh`/`.bash`/`.rb`/`.pl` have no
comparable common legitimate hidden-dotfile convention.

## Decode-then-execute as an obfuscation signature

A payload that never appears as a literal string in the source — because it's
base64/hex/binary-encoded and decoded only at runtime, immediately before
execution — evades a naive string-match scan for suspicious calls entirely. The
detectable shape is the *pairing*: a decode call (`base64.b64decode`, `binascii.
unhexlify`, `bytes.fromhex`, ...) within a small window of an execution sink
(`eval`/`exec`/`os.system`/`subprocess.*`), whether nested directly or via a
short assign-then-execute sequence. Decoding alone (a JWT segment, a config value)
is completely ordinary and must not fire — it's specifically the pairing with an
execution sink that's the signal. A long run of consecutive `\xNN` hex escapes in a
single literal is a related, independent signal (an inline obfuscated blob) even
without a visible exec call nearby in the same file.

## Install-time trust bypass

`pip install <name>`/`npm install <name>` resolve through the package registry,
which applies whatever integrity controls it offers (yanked-release enforcement,
package signing where available). Installing directly from a URL or a git ref
instead (`pip install git+https://...`, `npm install github:user/repo`) routes
around the registry entirely — there's no pin to an immutable released version, and
the exact code that lands can depend on whatever a *mutable* branch/tag currently
resolves to at install time. This is a common shape in a malicious agent-skill's own
install script: fetch the real payload from an attacker-controlled remote, bypassing
the registry's review/scanning surface. The detectable signal is on the install
*command* itself (a shell script or Dockerfile `RUN` line), a different source than
reading `package.json`/`requirements.txt` dependency *specifiers* — those two
signals are independent and complementary, not overlapping.

**A precision note worth stating explicitly:** the install-source check must
exclude private-registry-mirror configuration (`--index-url`/`--extra-index-url`/
`--trusted-host`) up front. That flag pattern also contains an `https://`
substring and is an extremely common, entirely legitimate enterprise pattern — a
naive "does this line contain `pip install` and `https://`" check would false-positive
on it constantly.

## What didn't make the cut

- **Hardcoded-secret patterns** — this source's own catalog largely duplicates what
  a dedicated secret scanner (gitleaks) already covers; no new signal.
- **Most command-injection sub-patterns** — duplicate coverage already provided by
  existing code-injection/command-injection static checks.
- **Resource-abuse patterns** (unbounded loops, excessive resource consumption) —
  too false-positive-prone for a static guard; legitimate heavy workloads and actual
  abuse look identical without a runtime signal.
