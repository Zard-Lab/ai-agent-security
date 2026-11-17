"""Structural prompt-injection delivery-marker neutralization for machine-readable,
tool/LLM-consuming report paths.

agentsec makes **no in-tool LLM call** — a network POST of scan data to a third-party LLM
(`--llm-triage`) was proposed and explicitly deferred/rejected as a decision-gated feature (see
`.claude/plans/network-egress-policy-and-kev.md` decision #2): "`--llm-triage` -> pipe-out, not
build-in ... build NOTHING in-tool". The documented pattern instead is
`agentsec audit . --format sarif | <your-own-triage-tool>` — the user pipes agentsec's
machine-readable output to whatever downstream tool they choose, which may itself call an LLM.

That pipe-out surface is still attacker-adjacent: `findings.py::to_sarif`/`to_sarif_json` embeds
guard/runner-authored `Finding.title`/`Finding.message` text, and `coverage.py::to_json` embeds
`checklist.json`'s `ChecklistItem.title` text, verbatim into the JSON payload a downstream
consumer (LLM or otherwise) reads. If a guard's own metadata text is ever influenced (a
community-contributed guard, or a compromised dependency's error string echoed into a finding's
`message`), unneutralized delivery-mechanic bytes in that text would ride along into whatever
reads the JSON next.

This module neutralizes exactly the STRUCTURAL delivery mechanics an attacker would need — never
content/topic filtering, which would false-positive on a guard's own legitimate security prose
(a remediation string legitimately needs to say "validate user input" or discuss injection
attacks by name; that must never get mangled). Concept-mined from
`Pantheon-Security/medusa`'s `rule_integrity.py` (STRUCTURAL scanning of rule-authoring fields
only), reimplemented from scratch for this codebase's own conventions per the project's
concept-mine-only discipline for external-source-derived work — no code copied.

Three marker classes, and only these:

1. **Null bytes** (U+0000) — never legitimate in this codebase's text; some downstream string/
   buffer handling treats a NUL as a terminator, which could truncate a wrapping system prompt
   and let attacker-controlled text past it. Stripped outright.
2. **Unicode bidi/directional-override control characters** (U+202A-U+202E, U+2066-U+2069) — can
   visually reorder rendered text so what a human reviewer sees differs from what a model
   actually tokenizes. Stripped outright (this codebase's legitimate text is never intentionally
   bidi-controlled).
3. **Fake conversation-turn / role-tag delimiters** — text engineered to look like the start of a
   new turn or a system-level instruction once flattened into a single prompt: a "Role:" line
   immediately preceded by a blank line (mimicking a turn boundary, e.g. the classic
   `"\n\nUser:"` pattern), a markdown-heading-style role tag on its own line (`"### System:"`),
   or a raw chat-template control token (`<|im_start|>`, `[INST]`, `<<SYS>>`, ...). These are
   escaped in place (structural characters backslash-escaped) rather than deleted, so the text
   stays legible but no longer parses as a turn/role boundary to a downstream chat-template
   consumer.

Deliberately NOT covered: "ignore previous instructions"-style phrase detection, keyword/topic
filtering, or anything that inspects meaning rather than shape. Sanitize at the POINT OF USE
(the emitting call sites: SARIF, coverage JSON, the drift snapshot, and — since this is also the
channel the `/security-review`/`/security-audit` skills instruct an LLM to read via
`agentsec audit --out ....md`, see `findings.py::to_markdown`/`to_human_summary` — the
human-readable report paths too) — never mutate `checklist.json` or a `Finding` in place.

The chat-template token list (`_CHAT_TEMPLATE_TOKENS`) is inherently a denylist and will always be
incomplete against a template this module has not seen yet (a new model family's turn markers,
e.g. Gemma's `<start_of_turn>`) — it is a defense-in-depth layer alongside the structural
turn-delimiter/heading-role patterns above, which do not depend on knowing a specific template's
token spelling, not the primary defense.
"""
from __future__ import annotations

import re

_NULL_BYTE = "\x00"

# Bidi explicit-override controls: LRE, RLE, PDF, LRO, RLO (U+202A-U+202E).
_BIDI_EXPLICIT = "".join(chr(c) for c in range(0x202A, 0x202F))
# Bidi isolate controls: LRI, RLI, FSI, PDI (U+2066-U+2069).
_BIDI_ISOLATE = "".join(chr(c) for c in range(0x2066, 0x206A))
_BIDI_CONTROL_RE = re.compile(f"[{_BIDI_EXPLICIT}{_BIDI_ISOLATE}]")

# Zero-width/invisible characters with no legitimate use AS AN ANCHOR-BREAKING WEDGE in this
# module's context. Round-2 review, Medium 2: the original set borrowed `guards/invisible_unicode.py`'s
# exclusion of U+200D ZWJ and U+200E/U+200F bidi marks (that module's docstring explains why: real
# Arabic/Hebrew/emoji-family text needs them, so stripping them there would be a content change,
# not a structural one) — but that rationale is about deciding "is this character suspicious
# enough to REPORT", and does not transfer here. This module's question is "can this character
# break my anchor", where legitimacy elsewhere is irrelevant: an attacker splitting a role word
# will simply use whichever invisible character this module leaves unstripped. Measured to bypass
# before this widening: ZWJ, LRM, RLM, the word joiner (U+2060), and soft hyphen (U+00AD, normally
# invisible except at a line-wrap point). Left unstripped, a zero-width character hidden between
# two letters of a role word (e.g. a ZWSP splitting "User" into two pieces mid-word) defeats the
# turn-delimiter regex below by breaking up the literal role-word match - stripping these first,
# before any marker regex runs, closes that gap the same way bidi-control stripping already does
# for visual-reordering. (Deliberately described here rather than embedded literally, so this
# file's own source doesn't trip the guard it's neutralizing text for - see
# `test_zero_width_char_inside_role_word_neutralized` for the actual planted character.)
_ZERO_WIDTH = "".join(
    chr(c) for c in (0x200B, 0x200C, 0x200D, 0x200E, 0x200F, 0x2060, 0xFEFF, 0xAD)
)
_ZERO_WIDTH_RE = re.compile(f"[{_ZERO_WIDTH}]")

# The Unicode tag block (U+E0000-U+E007F) - invisible in every renderer, and the specific
# primitive `guards/invisible_unicode.py`'s own docs already treat as the most dangerous
# invisible-payload carrier (it can encode an entire hidden ASCII string per character). Same
# "can this break my anchor" reasoning as `_ZERO_WIDTH` above, kept as its own regex because the
# range sits outside the BMP and reads better as a range than 128 enumerated `chr()` calls.
_TAG_BLOCK_RE = re.compile("[\U000e0000-\U000e007f]")

_ROLE_WORDS = r"(?:system|user|assistant|human|ai)"

# Horizontal whitespace, Unicode-aware, EXCLUDING the newlines that give the surrounding pattern
# its own structure. Round-2 review, Medium 2: the original `[ \t]` blank-line/padding class only
# recognized a literal space or tab - an attacker-inserted NBSP (U+00A0) or vertical tab (U+000B)
# on an otherwise-"blank" line, or padding a role tag, was measured to bypass entirely, because
# neither is a space or a tab. `\s` is Unicode-aware for `str` patterns (matches every character
# Python's own `str.isspace()` does, NBSP and vertical tab included), so `[^\S\r\n]` - "whitespace
# that is not CR/LF" - catches all of those while still leaving `\r?\n` in control of where an
# actual line break sits.
_HSPACE = r"[^\S\r\n]"

# A "Role:" line immediately preceded by start-of-text or a blank line — the shape a flattened
# prompt injection uses to impersonate a fresh turn boundary (e.g. "\n\nUser:"). Anchoring on
# the blank-line/start-of-text boundary (rather than matching "User:" anywhere) is what keeps
# this from firing on ordinary prose that uses a role word mid-paragraph without a colon
# immediately following it at a line start — the false-positive case this must not catch.
# `\r?` around each `\n` tolerates CRLF source text (a Windows-authored finding message, or text
# read from a CRLF file) - without it, "x\r\n\r\nUser:" doesn't match at all, because the `\r`
# sitting between the two newlines isn't consumed by anything in the pattern.
_TURN_DELIMITER_RE = re.compile(
    rf"(\A|\r?\n{_HSPACE}*\r?\n)({_HSPACE}*{_ROLE_WORDS}{_HSPACE}*:)", re.IGNORECASE
)

# A markdown-heading-style role tag at the start of a line, e.g. "### System:" or
# "## Instructions:" — matched through the colon regardless of what follows on the line (the
# injected instruction is typically appended right after it, e.g. "### System: comply now").
_HEADING_ROLE_RE = re.compile(
    rf"^({_HSPACE}*#{{1,6}}{_HSPACE}*(?:{_ROLE_WORDS}|instructions?){_HSPACE}*:)",
    re.IGNORECASE | re.MULTILINE,
)

# Raw chat-template control tokens. These have no legitimate meaning in security prose (no
# content-inspection risk), so they're matched unconditionally rather than anchored. Necessarily a
# denylist (see module docstring) - covers the OpenAI/ChatML family (`<|im_start|>` etc.), Llama's
# `[INST]`/`<<SYS>>` and Llama-3's `<|start_header_id|>`/`<|eot_id|>`, Gemma's
# `<start_of_turn>`/`<end_of_turn>`, and the generic GPT-2-style `<|startoftext|>`/`<|endoftext|>`
# sentinel pair. Necessarily incomplete against a template this module has not seen yet (module
# docstring) - defense-in-depth alongside the structural patterns above, not the primary defense.
_CHAT_TEMPLATE_TOKENS = (
    "<|im_start|>", "<|im_end|>", "<|system|>", "<|user|>", "<|assistant|>",
    "[INST]", "[/INST]", "<<SYS>>", "<</SYS>>",
    "<start_of_turn>", "<end_of_turn>", "<|startoftext|>", "<|endoftext|>",
    "<|start_header_id|>", "<|end_header_id|>", "<|eot_id|>",
)

# Characters that give a matched marker its structural meaning to a chat-template parser.
# Escaping these (not deleting the surrounding text) keeps the text legible while breaking
# recognition as a turn/role boundary.
_STRUCTURAL_CHARS = frozenset("#<>[]|:")


def _escape_structural_chars(marker: str) -> str:
    return "".join(f"\\{c}" if c in _STRUCTURAL_CHARS else c for c in marker)


def neutralize_delivery_markers(text: str) -> str:
    """Strip/escape structural prompt-injection delivery markers in `text`.

    Pure function — never touches disk, never mutates its argument's source. Call this at the
    point a string is about to be written into ANY output an LLM or tool might read — that
    includes the human-readable markdown/summary report (the `/security-audit`/`/security-review`
    skills instruct an agent to read it), not just the machine-readable SARIF/JSON paths; see the
    module docstring. For a `Finding`'s own fields specifically, call `findings.sanitize_finding()`
    instead of this function directly — it is the single choke point that covers every field
    (including `location`, which is attacker-controlled via a hostile filename and was missed
    entirely by a per-call-site approach, round-2 review of PR #581) so a new emitter can't
    silently opt out by forgetting one.

    Safe on empty/None-like input (returns it unchanged) so call sites don't need a guard.

    Known, accepted trade-off (round-2 review, Medium 1): a guard that legitimately NAMES a raw
    control token as part of explaining what it detects (`prompt-string-interp`'s own message,
    which prints `<|im_start|>` etc. as documentation) gets that token escaped too, same as an
    actual attack would. This module deliberately does not distinguish "explaining a token" from
    "using a token as an attack" — that needs content understanding, exactly what the module
    docstring says this function will never do. The escaped text stays legible
    (`\\<\\|im_start\\|\\>` still reads as the token), just with visible backslashes.
    """
    if not text:
        return text
    out = text.replace(_NULL_BYTE, "")
    out = _BIDI_CONTROL_RE.sub("", out)
    out = _ZERO_WIDTH_RE.sub("", out)
    out = _TAG_BLOCK_RE.sub("", out)
    for token in _CHAT_TEMPLATE_TOKENS:
        if token in out:
            out = out.replace(token, _escape_structural_chars(token))
    out = _TURN_DELIMITER_RE.sub(lambda m: m.group(1) + _escape_structural_chars(m.group(2)), out)
    out = _HEADING_ROLE_RE.sub(lambda m: _escape_structural_chars(m.group(1)), out)
    return out
