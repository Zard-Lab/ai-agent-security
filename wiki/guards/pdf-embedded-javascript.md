---
type: Guard
title: "pdf-embedded-javascript"
description: "No embedded JavaScript / auto-run action in a PDF file."
timestamp: "2026-07-12T21:19:18+08:00"
guard_id: "pdf-embedded-javascript"
checklist_section: ["3a"]
standards: ["OWASP:A03"]
---

# No embedded JavaScript / auto-run action in a PDF file

_Author — 2026-07-12_

---

## The threat

The PDF format allows a document to carry executable behavior: a `/JS`/`/JavaScript`
action embeds real JavaScript that Adobe Reader/Acrobat execute by default, an
`/OpenAction` triggers automatically the moment the document is opened (frequently
pointing straight at a `/JS` action), and a `/Launch` action runs an external program
or command. Any upload path or bundled-asset path that treats a `.pdf` as an inert
document (an invoice, a resume, an agent-skill reference doc) can end up serving one
of these. `/Launch` in particular is a long-standing PDF remote-code-execution vector.
CWE-95 (Improper Neutralization of Directives in Dynamically Evaluated Code),
OWASP:A03.

## Why this guard fits the stack

Mirrors `svg-embedded-script`'s rationale one file-format over: `content-type-magic-
bytes` confirms a file's declared type matches its magic bytes, but a well-formed PDF
(correct header, correct magic bytes) can still carry an embedded action — magic-byte
validation cannot see that. This guard inspects PDF *content* directly, and applies
universally (not gated on a stack feature) so it also catches a malicious PDF checked
into the repo as a bundled asset, with no upload path required.

## Detection design

1. **`applies()` gate** — always `True` (mirrors `svg-embedded-script` /
   `invisible-unicode`): PDF-as-attack-vector is a property of the file, not the stack.
2. **Files scanned** — every `.pdf` file under the repo (`iter_files(root, (".pdf",))`),
   read as `latin-1` text with `errors="ignore"` (not `utf-8`) — PDF bytes are not
   valid UTF-8 in general, and `latin-1` maps every byte 0-255 to a single codepoint
   1:1, so the scan never silently drops or merges bytes the way `utf-8`+`errors=
   "ignore"` could; non-product paths (test fixtures) are skipped via
   `is_nonproduct_path`.
3. **Patterns** — three independent literal markers, each its own rule, matched
   against the raw text: these keys live in PDF object *dictionaries*, which are
   never compressed even when a page's content *stream* is (only the stream's data
   is, typically via FlateDecode) — so a plain text scan finds them without needing
   to parse or decompress the PDF's object structure.
   - `js-action`: `/JS` or `/JavaScript` (word-boundaried).
   - `open-action`: `/OpenAction` (word-boundaried).
   - `launch-action`: `/Launch` (word-boundaried).
   Each rule fires at most once per file (first match), on the line the marker starts.
4. **Pragma** — `security: allow-pdf-embedded-javascript` anywhere in the file
   silences the whole file, checked before any rule runs.
5. **Severity / standards** — `js-action` and `launch-action` are HIGH.
   `open-action` is severity-adaptive: a **lone** `/OpenAction` is MEDIUM (routinely
   benign — `/OpenAction [3 0 R /Fit]`, a standard LaTeX/hyperref/pandoc initial-view
   action), escalating to HIGH only when the file ALSO carries a `/JS`/`/JavaScript`
   action (the dangerous "auto-run script on open" pairing). Rules are
   `pdf-embedded-javascript/{js-action,open-action,launch-action}`, `OWASP:A03`
   (checklist item also carries `CWE-95`).

## When NOT to flag

- A plain PDF with none of the three markers (the overwhelming majority of real
  document uploads) stays silent.
- A non-`.pdf` file that happens to contain the literal text `/JavaScript` (e.g. a
  changelog mentioning the PDF spec) is out of scope for this guard.

## Tests

| Test | What it checks |
|---|---|
| `test_fires_on_js_action` | `/S /JavaScript /JS (...)` fires `js-action`, HIGH |
| `test_lone_open_action_is_medium` | a bare `/OpenAction [3 0 R /Fit]` (no `/JS`) fires `open-action` at MEDIUM |
| `test_open_action_with_js_is_high` | `/OpenAction` + an embedded `/JS` escalates `open-action` to HIGH |
| `test_fires_on_launch_action` | `/S /Launch /F (calc.exe)` fires `launch-action` |
| `test_passes_plain_pdf` | a catalog/pages-only PDF with none of the markers stays silent |
| `test_passes_non_pdf_file` | the same markers in a `.txt` file are out of scope |
| `test_pragma_opt_out` | the file-wide pragma silences all three rules |

## Known bypasses

- A PDF whose object dictionary is itself compressed via an object stream
  (`/Type /ObjStm`, PDF 1.5+ cross-reference streams) can hide these keys from a
  plain text scan entirely — decompressing object streams would require real PDF
  parsing, out of scope for a dependency-free static guard.
- Splitting or obfuscating the marker across PDF syntax constructs a real parser
  would normalize (e.g. hex-encoded names, `#4A#53` for `/JS`) evades the literal
  match.
- A `/Launch`/`/JS` action nested inside an encrypted PDF (`/Encrypt` dictionary
  present) is unreadable as plain text at all; this guard has no decryption support.

## What this guard does NOT prove

A silent result does not prove a PDF is free of executable behavior — it only means
none of these three specific literal markers were found via a plain-text scan. It
does not parse the PDF's cross-reference table or object streams, does not follow
embedded-file (`/EmbeddedFile`) attachments (which can carry their own payloads
recursively — a PDF-in-a-PDF), and does not evaluate whether any JavaScript found is
actually harmful vs. benign (e.g. legitimate form-validation script in a fillable
PDF) — this guard is a presence check, not a behavioral one.

# Citations

[1] agentsec checklist item `3a-pdf-embedded-javascript` (§3a)
[2] OWASP:A03
