---
type: Guard
title: "js-buffer-noassert"
description: "Buffer read/write call passes noAssert=true."
timestamp: "2026-07-13T21:44:04+08:00"
guard_id: "js-buffer-noassert"
checklist_section: ["8"]
standards: ["OWASP:A06"]
---

# Buffer read/write call passes noAssert=true

## Threat

Node's `Buffer` read/write methods (`readUInt32LE`, `writeInt8`, ...) accept an
optional final `noAssert` boolean. Node's own documentation marks it
deprecated for exactly this reason: when `true`, the offset argument is never
validated against the buffer's actual bounds before the read or write
executes. An attacker-influenced offset — e.g. derived from a length field in
a parsed network packet or file format — combined with `noAssert: true` lets
a read run past the end of the buffer (leaking adjacent heap memory into the
parsed result) or a write run past the end (corrupting adjacent memory). This
is CWE-119 (Improper Restriction of Operations within Bounds of a Memory
Buffer), OWASP-Web:A6.

## Why this guard fits the stack

`noAssert: true` is a well-known, static, textual pattern in Node.js binary
parsing code (protocol parsers, file-format readers, buffer pooling) — exactly
the kind of check agentsec's zero-dependency guard model is built for. The
rule is adapted from njsscan's `buffer_noassert.yaml` (`ajinabraham/njsscan`,
real Semgrep-syntax rule `buffer_noassert` — 26 pattern variants across every
read/write width and endianness, all mapped to one rule id), verified against
the actual fetched source rather than taken from a description of it.

## Detection design

1. `applies()` gates broadly on `"javascript" in profile.features or
   "typescript" in profile.features` — not a specific framework feature like
   `express`. `Buffer` is a Node.js-only global with no browser equivalent, so
   it doesn't exist outside a JS/TS/Node context at all; the language check
   alone already keeps false-positive risk low without needing a narrower
   stack signal.
2. Scans all `.js`, `.jsx`, `.ts`, `.tsx` files (`iter_files`), line by line.
3. Skips a file entirely if the pragma comment is present anywhere in it (a string literal quoting it
   does not count, #424); skips
   an individual line if the pragma is on that same line.
4. A single regex alternation covers all 26 njsscan method-name variants,
   matching a call whose final argument is the literal `true`.

### Regex used

```python
_METHODS = (
    "readUInt8", "readUInt16LE", "readUInt16BE", "readUInt32LE", "readUInt32BE",
    "readInt8", "readInt16LE", "readInt16BE", "readInt32LE", "readInt32BE",
    "readFloatLE", "readFloatBE", "readDoubleLE", "readDoubleBE",
    "writeUInt8", "writeUInt16LE", "writeUInt16BE", "writeUInt32LE", "writeUInt32BE",
    "writeInt8", "writeInt16LE", "writeInt16BE", "writeInt32LE", "writeInt32BE",
    "writeFloatLE", "writeFloatBE", "writeDoubleLE", "writeDoubleBE",
)
_NOASSERT_CALL = re.compile(
    r"\.(?:" + "|".join(_METHODS) + r")\s*\([^)]*,\s*true\s*\)"
)
```

All 26 variants map to a single rule slug (`noassert-true`), mirroring
njsscan's own single-rule-id design.

## Severity rationale

**MEDIUM.** An out-of-bounds Buffer access is real memory unsafety, but unlike
a direct code-execution primitive (e.g. `nodeIntegration: true` in the
Electron guard) it requires the offset to actually be attacker-influenced and
the surrounding code to do something exploitable with the leaked/corrupted
bytes — a real but conditional risk, matching the severity of comparable
memory/bounds guards elsewhere in this codebase (e.g. `weak-crypto`, `tls-
verify-disabled`).

## When NOT to flag

Any Buffer read/write call with no third/second `true` literal argument
(including the common, safe default of simply omitting `noAssert` entirely)
never matches — the regex requires the literal trailing `, true)`.

## Known bypasses / false negatives

| Bypass | Description |
|--------|-------------|
| Computed boolean | `buf.readUInt32LE(offset, shouldSkipAssert)` where the variable evaluates to `true` at runtime — the guard matches the literal token `true`, not a computed expression. |
| Nested-paren offset argument | `buf.writeInt8(getValue(), computeOffset(x, y), true)` — the bounded `[^)]*` capture between the opening paren and the trailing `, true)` can be broken by a nested function call containing its own closing paren, the same tradeoff several other bounded-capture regexes in this codebase already accept. |
| Nonstandard aliasing | `const r = buf.readUInt32LE.bind(buf); r(offset, true);` — the guard matches a direct method-call shape, not an aliased/bound reference. |

## What this guard does NOT prove

A silent guard does not prove every Buffer offset in the codebase is
attacker-uninfluenced or otherwise safe — it only proves that none of the 26
checked read/write methods pass the literal `noAssert: true` value. A buffer
overflow via some other API path (e.g. manual pointer arithmetic in native
addons, or `Buffer.allocUnsafe` misuse) is outside this guard's scope.

## False positive scenarios

| Scenario | Why it fires | Mitigation |
|----------|-------------|------------|
| Genuinely trusted, fixed-size internal buffer (e.g. parsing a hardcoded constant-length header the app itself constructed) | Guard cannot distinguish attacker-influenced offsets from ones the app fully controls. | Add a `// security: allow-js-buffer-noassert` comment after confirming the offset can never be attacker-influenced. |
| Performance-critical hot path where bounds-checking overhead was intentionally profiled away | A deliberate, reviewed tradeoff. | Add the pragma with a comment explaining the profiling decision. |

## Checklist items flipped

| ID | Before | After | Reason |
|----|--------|-------|--------|
| `8-buffer-noassert` | (new item) | `covered` | Guard statically detects Buffer read/write calls with `noAssert: true`; fires MEDIUM; silenceable per-file/per-line. |

## Tests

| Test | Validates |
|------|-----------|
| `test_js_buffer_noassert_flags_read_call` | True positive: `buf.readUInt32LE(offset, true)` fires. |
| `test_js_buffer_noassert_flags_write_call` | True positive: `buf.writeInt8(value, offset, true)` fires. |
| `test_js_buffer_noassert_silent_without_noassert_arg` | False positive guard: the same read call with no third argument at all — no finding. |
| `test_js_buffer_noassert_silent_when_noassert_false` | False positive guard: `noAssert` explicitly `false` — no finding. |
| `test_js_buffer_noassert_pragma_silences` | Pragma: inline suppress comment silences the finding. |
| `test_js_buffer_noassert_not_applies_without_js_or_ts` | Feature gate: `applies()` is `False` when neither `"javascript"` nor `"typescript"` is in `profile.features`. |

# Citations

[1] agentsec checklist item `8-buffer-noassert` (§8)
[2] OWASP:A06
