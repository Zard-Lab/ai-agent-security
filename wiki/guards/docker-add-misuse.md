---
type: Guard
title: "docker-add-misuse"
description: "Dockerfile ADD used instead of COPY/RUN curl."
timestamp: "2026-07-12T00:44:21+08:00"
guard_id: "docker-add-misuse"
checklist_section: ["6c"]
standards: ["CWE-494", "OWASP:A08"]
---

# Dockerfile ADD used instead of COPY/RUN curl

_Author — 2026-07-12_

---

## The threat

Docker's `ADD` instruction silently does more than `COPY`: it auto-extracts a recognized
local archive at the destination, and it can fetch a remote URL directly with no
integrity verification available in the instruction itself. Both behaviors are implicit —
nothing in a bare `ADD app.tar.gz /app` line signals "this will be extracted," and nothing
in `ADD https://example.com/x.sh /tmp/x.sh` signals "this fetch has no checksum." Either
shape is a route for a tampered or unexpected artifact to enter an image layer without a
human noticing at Dockerfile-review time. OWASP:A08 (Software and Data Integrity
Failures) / CWE-494 (Download of Code Without Integrity Check).

Source: two real, independently verified terrascan policies in
[tenable/terrascan](https://github.com/tenable/terrascan), combined here into one guard
because they're the same underlying anti-pattern (`ADD` doing more than the author
intended):

**`pkg/policies/opa/rego/docker/docker_add/addinsteadofcopy.rego`** — fires when `ADD`'s
source is a local `.tar`/`.tar.gz`/`.tgz`/`.tar.bz2` file (should be `COPY`, or an explicit
`RUN tar -xzf` if extraction is really wanted).

**`pkg/policies/opa/rego/docker/docker_add/CurlWgetinsteadofAdd.rego`** — fires when
`ADD`'s source matches `re_match("https?", config)` (a remote URL; recommendation is
`RUN curl`/`wget` instead, verified by direct fetch):

```
{{.prefix}}{{.name}}{{.suffix}}[add.id]{
    add := input.docker.add[_]
    is_string(add.config)
    config := add.config
    checkWget(config)
}
checkWget(config) { re_match("https?", config) }
```

## Why this guard fits the stack

`ADD` is a common Dockerfile primitive across any Python/Node backend or frontend build;
`ADD <url>` in particular shows up in quick-start scripts that fetch an installer, and
`ADD app.tar.gz` shows up when a build artifact is staged as a tarball rather than a
directory — both patterns are plausible in the target FastAPI + React shape.

## Detection design

1. `applies()` — always true; Dockerfiles are stack-agnostic.
2. Scans every file from `iter_dockerfiles(root)`.
3. Every `ADD` instruction is matched by `_ADD_INSTRUCTION`. `_add_sources()` extracts
   every SOURCE token (all but the last — the destination) from both the shell form
   (`ADD a.tar.gz /dest`, with `--chown=`/`--chmod=`/`--checksum=` flags stripped first)
   and the JSON-array form (`ADD ["a.tar.gz", "/dest"]`).
4. Each source token is checked in order:
   - `_URL_SRC` (`^https?://`) → `docker-add-misuse/add-remote-url` (MEDIUM).
   - `_ARCHIVE_EXT` (`.tar`/`.tar.gz`/`.tar.bz2`/`.tar.xz`/`.tgz`/`.tbz2`, case-
     insensitive) → `docker-add-misuse/add-local-archive` (MEDIUM).
   - One finding per `ADD` line (first match wins) — enough signal without flooding a
     Dockerfile that ADDs several archives.
5. Inline opt-out: `# security: allow-docker-add`.
6. Standards: `["OWASP:A08", "CWE-494"]`.

## When NOT to flag

- `ADD` of an ordinary source file or directory that is neither an archive nor a URL —
  the overwhelming majority of real `ADD` usage, and functionally identical to `COPY` in
  that case (no auto-extraction, no remote fetch) — must stay silent.
- `COPY` (not `ADD`) of a `.tar` file never auto-extracts regardless of extension — must
  stay silent; this guard only inspects `ADD` instructions.
- A `.zip` archive is NOT auto-extracted by Docker's `ADD` (only tar-family formats are),
  so `ADD app.zip /app` correctly stays silent — this is accurate fidelity to Docker's
  real `ADD` semantics, not a gap.
- The `# security: allow-docker-add` pragma — for a build stage where the extraction or
  unverified fetch is intentional and reviewed.

## Tests

| Test | What it checks |
|---|---|
| `test_docker_add_misuse_local_archive_fires` | `ADD app.tar.gz /app` → fires `add-local-archive` |
| `test_docker_add_misuse_remote_url_fires` | `ADD https://.../install.sh ...` → fires `add-remote-url` |
| `test_docker_add_misuse_json_array_url_fires` | JSON-array form `ADD ["https://...", "/dest"]` → fires |
| `test_docker_add_misuse_plain_file_silent` | `ADD app.py /app/app.py` → silent (FP-bait) |
| `test_docker_add_misuse_copy_of_tar_silent` | `COPY app.tar.gz /app` (not ADD) → silent (FP-bait) |
| `test_docker_add_misuse_directory_silent` | `ADD mydir /app/mydir` → silent |
| `test_docker_add_misuse_pragma_silences` | Pragma present, both patterns on one Dockerfile → silent |
| `test_docker_add_misuse_applies_always` | `applies()` is `True` for any profile |

## Known bypasses

- **A `.zip`/`.7z`/other non-tar archive fetched via `ADD <url>`** would correctly fire as
  `add-remote-url` (the URL pattern matches first), so no coverage gap there — but a
  LOCAL `.zip` source would not fire at all, which is correct (Docker doesn't
  auto-extract zips), not a bypass.
- **An indirect archive reference via a build `ARG`** (`ARG SRC=app.tar.gz` then
  `ADD $SRC /app`) is not resolved — the guard sees the literal token `$SRC`, which
  matches neither the URL nor archive-extension pattern, so it stays silent. Same class
  of limitation as the other Dockerfile-parsing guards in this batch (no build-arg
  expansion without executing the build).
- **A URL-shaped local path** (a filename that happens to start with `http` but isn't a
  real URL) is a purely theoretical edge case not worth defending against.

## What this guard does NOT prove

- That a `RUN curl`/`RUN tar -xzf` replacement pattern, if adopted, actually verifies a
  checksum — this guard only proves the anti-pattern (`ADD` doing the fetch/extraction
  implicitly) is gone from the Dockerfile, not that the remediation includes real
  integrity verification.
- That the local archive being ADDed doesn't itself contain a legitimately vetted, signed
  artifact — the guard flags the INSTRUCTION shape, not the artifact's actual provenance.

# Citations

[1] agentsec checklist item `6c-docker-add-misuse` (§6c)
[2] CWE-494
[3] OWASP:A08
