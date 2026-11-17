---
type: Guard
title: "content-type-magic-bytes"
description: "File upload validates Content-Type header only — magic bytes not checked (CWE-434)."
timestamp: "2026-06-28T11:57:06+08:00"
guard_id: "content-type-magic-bytes"
checklist_section: ["3a"]
standards: ["ASVS:5.2.2", "OWASP:A03"]
---

# File upload validates Content-Type header only — magic bytes not checked (CWE-434)

## Threat

**CWE-434 / Unrestricted File Upload via Content-Type bypass.**

The `Content-Type` HTTP header is fully attacker-controlled. Any file upload handler that
uses `file.content_type` as the sole validation gate can be bypassed with a forged header
(`curl -F "file=@malware.php;type=image/jpeg"`). Real MIME type must be inferred from the
file's magic bytes — the first bytes embedded by the format, not sent by the client.

Attack scenarios:
- Upload a PHP/JSP file as `image/jpeg` → execute code on the server.
- Upload an SVG with embedded `<script>` as `image/svg+xml` → stored XSS when served.
- Upload a polyglot (valid JPEG header + embedded HTML) → browser renders as HTML.

## Detection design

**File-level check with three gates:**

1. `UploadFile` must appear in the file (FastAPI file upload).
2. `file.content_type` or `content_type` must be referenced (upload handler IS checking type).
3. No magic-byte validation signal present — checked by looking for any of:
   - `import magic` / `import filetype` / `import imghdr` / `import sndhdr` / `import puremagic`
   - `from magic import` / `from filetype import`
   - `from PIL` / `Image.open(` / `.verify(` — Pillow opens-and-parses the image, which is
     *stronger* content validation than a magic-byte peek (PR #206 review)
   - `.read(N)` with any explicit byte count (`\.read\s*\(\s*\d+\s*\)`) — a manual header/signature
     read; broadened from a fixed 4–512 list so a `.read(1024)` header read is not a false positive
     (PR #206 review)
   - `file_signature` / `magic_bytes` / `header_bytes` — common variable names

If gates 1 and 2 pass but gate 3 does not: flag. The finding location is the first
`content_type` reference line.

**`applies()` gate:** requires both `python` AND `fastapi` in `profile.features` — reduces
noise on non-FastAPI Python code where `content_type` is a different concept.

## Tests

| Test | Expected |
|---|---|
| `UploadFile` handler checks `content_type` header only | 1 finding, MEDIUM |
| Same handler also imports `magic` library | silent |
| Same handler also imports `filetype` library | silent |
| Handler reads any byte count (`.read(12)`, `.read(1024)`) | silent |
| Handler calls `Image.open(...).verify()` (Pillow) | silent |
| Handler has `UploadFile` but no `content_type` check | silent |
| File has `content_type` but no `UploadFile` | silent |
| `# security: allow-content-type-header-only` pragma | silent |
| `python` in features but not `fastapi` | `applies()` False |

## Known bypasses / limitations

- Magic validation in a separate helper module not imported in the upload file: will not fire.
- `filetype` or `magic` installed but used elsewhere in the file (not for this upload): may
  produce a false negative.
- Does not verify that the magic-byte check is done BEFORE processing the file.

## What this guard does NOT prove

- That the allowed MIME types list is correct for the use case.
- That files are stored in a non-executable location after upload.
- That upload size limits are enforced (that's `upload-no-size-limit`).

# Citations

[1] agentsec checklist item `3a-content-type-magic-bytes` (§3a)
[2] ASVS:5.2.2
[3] OWASP:A03
