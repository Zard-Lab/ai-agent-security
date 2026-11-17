---
type: Guard
title: "unrestricted-file-upload"
description: "Upload saved under the client-supplied filename — path traversal + dangerous-type write."
timestamp: "2026-06-20T11:47:02+08:00"
guard_id: "unrestricted-file-upload"
checklist_section: ["3a"]
standards: ["CWE-434", "OWASP:A01", "OWASP:A03"]
---

# Upload saved under the client-supplied filename — path traversal + dangerous-type write

Flags an uploaded file written to disk under the client-supplied `.filename`. Closes the new checklist
item `3a-upload-filename-sanitized`. OWASP:A01 / OWASP:A03, CWE-434 (and CWE-22 path traversal).

## Provenance

This is the first guard the **autonomous coverage differ found on its own**: the CWE Top 25 scorecard
showed CWE-434 (Unrestricted Upload) as the single in-scope, buildable gap. Phase 0 of the director plan
closes that loop end-to-end (differ found it → built → verified → shipped).

## The threat

A FastAPI/Starlette `UploadFile` carries a client-controlled `.filename`. Writing it to disk directly
(`open(f"uploads/{file.filename}", "wb")`) lets the attacker choose the **name and extension**: a
`.html`/`.svg`/`.php` to get a dangerous type served back (stored XSS or code execution depending on the
serving setup), or a `../` to escape the upload directory (path traversal). The fix is a server-generated
name (a uuid) plus an allowlisted extension; the raw `.filename` must never reach the path.

## Exploitability rationale

The item and the **finding** are both HIGH: writing an upload under the client filename is a concrete,
high-confidence bug (path traversal plus dangerous-type write, occasionally RCE). It is not auto-critical
only because the blast radius depends on where the directory is served from, which the static scan cannot
see; the pragma covers a genuinely sandboxed case.

## What counts as a hit (and what doesn't)

A line where a write/path sink takes the client `.filename`:

- `open(... .filename ...)`, `os.path.join(... .filename)`, `shutil.copy/copyfileobj/copy2/move(... .filename)`,
  or a `pathlib` join `dir / x.filename`.

It does **not** fire on: a server-generated name (`open(f"uploads/{uuid4()}.bin", ...)`), merely reading
the attribute (`name = file.filename`, `logger.info(file.filename)`), or inspecting it
(`os.path.splitext(file.filename)`). The sink + `.filename` co-requirement is what keeps it precise.

## When NOT to flag (and the pragma)

- The path uses a server-generated name, not `.filename` → silent.
- `.filename` is only read/logged/inspected, never written to a path → silent.
- A reviewed, sandboxed case → suppress the line with `# security: allow-upload-filename`.

## Known bypasses (honest limits)

- **Indirection.** `dest = f"uploads/{file.filename}"` on one line then `open(dest, "wb")` on another is
  not traced (a deliberate false negative).
- **Non-FastAPI uploads.** Gated on `fastapi`; a Flask `request.files[...].filename` write is out of scope
  here (the flagship stack is FastAPI).
- **Renamed attribute.** Copying `.filename` into a variable with a different name defeats the match.

## What this guard does NOT prove

It proves the client filename reaches a write sink on one line; it does not verify the serving
configuration, the size cap, or the content-type/magic-byte validation (those are the sibling manual
items `3a-upload-size-cap` / `3a-content-type-magic-bytes`). Absence of a finding ≠ uploads are safe. It
is the fast, dep-free, high-precision static check for the most damaging upload mistake.

# Citations

[1] agentsec checklist item `3a-upload-filename-sanitized` (§3a)
[2] CWE-434
[3] OWASP:A01
[4] OWASP:A03
