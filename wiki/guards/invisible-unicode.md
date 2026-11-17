---
type: Guard
title: "invisible-unicode"
description: "No invisible Unicode-tag smuggling in repo text."
timestamp: "2026-06-17T10:40:51+08:00"
guard_id: "invisible-unicode"
checklist_section: ["3b", "4"]
standards: ["OWASP-LLM:LLM01"]
---

# No invisible Unicode-tag smuggling in repo text

Scans repo text for code points in the Unicode tag block **U+E0000–U+E007F** and flags any file that
contains them. Also detects zero-width and Unicode format characters used for the same obfuscation
purpose. Closes checklist item `3b-invisible-unicode-scan`. A **universal** guard (applies to any stack).

## The threat

The tag block is invisible in every editor and renderer, yet an LLM reads it as ordinary text. The
Glassworm / ASCII-smuggling class hides prompt-injection instructions there: a file passes human
review looking clean, while carrying a payload that a model (or a copy-paste into one) will obey. The
block has no legitimate use in source or documentation, so any occurrence is suspicious. OWASP-LLM:LLM01.

## Detection patterns

### Rule: `invisible-unicode/hidden-tag-chars` (MEDIUM)

Flags any line containing code points in the Unicode tag block U+E0000–U+E007F. These have no
legitimate use in source or docs. Fires once per file (the first matching line).

### Rule: `invisible-unicode/hidden-zwj-chars` (MEDIUM) — EXT-2A

Flags a line containing one of a **deliberately small** set of zero-width characters used to hide
injections from human reviewers while remaining readable to LLMs:

- **U+200B** — zero-width space
- **U+200C** — zero-width non-joiner
- **U+FEFF** — zero-width no-break space, **only when NOT a leading byte-order mark** (a U+FEFF at
  file position 0 is a standard BOM and is exempt; a mid-line U+FEFF still fires)

Characters with heavy legitimate use are **deliberately excluded** (narrowed after review):
**U+200D** (zero-width joiner, *required* in emoji families like 👨‍👩‍👧 and Indic/Arabic shaping) and
**U+200E / U+200F** (LTR/RTL bidi marks, *required* in Arabic/Hebrew and mixed-direction text). Flagging
them would punish correct i18n and emoji-bearing files. Fires once per file (MEDIUM).

Same pragma: `# security: allow-invisible-unicode`.

## Exploitability rationale

MEDIUM. The payload is real (hidden model instructions) but it only bites where the text reaches an
LLM or an agent; it is not a direct code-execution sink. Severity matches the checklist item.

## Why universal (the baseline-tier example)

Invisible smuggling is a property of *text*, not of a framework, so `applies()` returns `True` for any
repo. This is the first guard explicitly in the "baseline" tier — the security floor that runs before
(and regardless of) stack detection.

## When NOT to flag (and the pragma)

- **Clean text** — ordinary ASCII and normal accented/Unicode characters (café, ünïcode, emoji) are
  not in the tag block or zero-width set → silent.
- A file that legitimately needs these code points → add a
  `# security: allow-invisible-unicode` line anywhere in it.

## Known bypasses (honest limits)

- The zero-width set (U+200B–U+200F, U+FEFF) can appear legitimately in some RTL scripts and at
  file BOMs. The guard flags them in source/docs context where they are almost always smuggling.
- Only scans known text suffixes; a payload in an unusual extension or a binary blob is missed.

## What this guard does NOT prove

It proves the scanned text files are free of tag-block and zero-width smuggling; it does not scan
binary assets, uploaded content at runtime, or non-text formats. Absence of a finding ≠ no
hidden-instruction risk in data the app ingests at runtime.

# Citations

[1] agentsec checklist item `3b-invisible-unicode-scan` (§3b)
[2] agentsec checklist item `4-glassworm-ingest-scan` (§4)
[3] OWASP-LLM:LLM01
