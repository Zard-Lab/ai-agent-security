---
type: Guard
title: "js-http-to-file-access"
description: "HTTP response data written directly to the filesystem."
timestamp: "2026-08-07T07:20:02+08:00"
guard_id: "js-http-to-file-access"
checklist_section: ["3a"]
standards: ["CWE-912", "OWASP:A08"]
---

# HTTP response data written directly to the filesystem

_Author — 2026-08-07_

---

## The threat

Writing an HTTP response body straight to the filesystem — with no validation of its
content-type, size, or integrity, and no control over the destination path beyond what the
calling code passes — hands whoever controls the remote server (or anyone able to intercept
or redirect the request) an arbitrary file write onto the app's own disk. Depending on the
destination, that ranges from disk exhaustion to overwriting an executable or config file
the app later loads — a backdoor primitive. CWE-912 (Hidden Functionality) / CWE-434
(Unrestricted Upload of File with Dangerous Type) — CodeQL's own dual mapping for this exact
query. OWASP:A08 (Software and Data Integrity Failures). codeql `@security-severity 6.3`.

## Why this guard fits the stack

Two idioms show up repeatedly in Node download/proxy/caching code:

```js
// Streaming
https.get(url, (response) => {
  response.pipe(fs.createWriteStream(dest));
});

// Buffered (axios)
const response = await axios.get(url, { responseType: 'arraybuffer' });
fs.writeFileSync(dest, response.data);
```

Neither validates what actually came back before it lands on disk. agentsec's existing
`unrestricted-file-upload` guard covers the *inbound* direction (a client uploading a file to
the app); this is the mirror-image *outbound-fetch-then-write* direction, which nothing in
the checklist covered before this guard.

## Detection design

1. **`applies()` gate** — `"express" in profile.features`.
2. **Files scanned** — `iter_files(root, (".js", ".jsx", ".ts", ".tsx"))`, skipping
   `is_nonproduct_path`.
3. **Pattern, file-scoped in two parts** (the HTTP call and the file write are typically
   separate statements, same as `js-host-header-email-link`):
   - File-level gate: `_HTTP_CLIENT_INDICATOR` — `axios`, `https.get(`/`https.request(`,
     `http.get(`/`http.request(`, or `fetch(`.
   - Line-level check (only on files that passed the gate): either
     `_PIPE_TO_FILE` (`.pipe(fs.createWriteStream(...))` — the streaming shape) OR
     `_RESPONSE_DATA_TO_FS_WRITE` (`fs.writeFile(Sync)?(..., <expr>.data)` /
     `...(..., <expr>.body)` — the buffered shape; `.data` is axios's response-body
     property, `.body` covers `fetch`'s `Response.body`).
4. **Pragma** — `// security: allow-js-http-to-file-access` on the write line.
5. **Severity/rule** — HIGH, `js-http-to-file-access/response-to-filesystem`, standards
   `["OWASP:A08", "CWE-912"]`.

## When NOT to flag

- A file with no HTTP-client indicator at all — a plain `stdin.pipe(fs.createWriteStream(...))`
  or piping between two local streams stays silent (the file-level gate never opens).
- A file that does call an HTTP client, but writes something other than the response body to
  disk (a config object, a computed report, a hardcoded string) — `.data`/`.body` isn't
  present in the write call's arguments, so it stays silent.
- A commented-out write, or one suppressed with the inline pragma.

## Tests

| Test | What it checks |
|---|---|
| `test_js_http_to_file_access_flags_streaming_pipe` | `response.pipe(fs.createWriteStream(...))` off an `https.get` fires |
| `test_js_http_to_file_access_flags_buffered_axios_data` | `fs.writeFileSync(dest, response.data)` off an axios call fires |
| `test_js_http_to_file_access_silent_without_http_client` | A file-write pipe with no HTTP-client indicator in the file stays silent (FP-bait) |
| `test_js_http_to_file_access_silent_unrelated_write` | An HTTP-client file writing something other than `.data`/`.body` stays silent (FP-bait) |
| `test_js_http_to_file_access_pragma` | Inline pragma suppresses |
| `test_js_http_to_file_access_not_applies_without_express` | `applies()` is `False` without the `express` feature |

## Known bypasses

- **File-scoped correlation, not a true dataflow link**: if a file both (a) calls an HTTP
  client anywhere and (b) pipes some *unrelated* stream to `fs.createWriteStream` anywhere
  else, this guard still fires — it does not confirm the piped stream is actually the HTTP
  response. This is an accepted, documented over-approximation, same trade-off already made by
  `js-host-header-email-link` and `js-cors-wildcard`'s credential-reflection check.
- **A wrapped/renamed HTTP client** (a custom `httpClient.js` module that re-exports `axios`
  under a different name, or a GraphQL/gRPC client fetching a file URL) is invisible to
  `_HTTP_CLIENT_INDICATOR`.
- **`.data`/`.body` read into an intermediate variable first**, then written on a later line
  (`const body = response.data; fs.writeFileSync(dest, body);`) — the write line no longer
  contains the literal `.data`/`.body` token, so `_RESPONSE_DATA_TO_FS_WRITE` misses it.
- **Async streaming without the literal `.pipe(` call** (manually reading chunks off a
  `Readable` and writing them with `fs.appendFileSync` in a loop) has no matching literal
  shape at all.

## What this guard does NOT prove

A silent result does not mean an app never writes untrusted network data to disk — only that
no line in a file that also calls a recognized HTTP client matches the two specific literal
shapes above. Any true dataflow-linked variant (variable indirection, an unrecognized client
library, a custom streaming loop) is outside this guard's reach without a real dataflow engine.

# Citations

[1] agentsec checklist item `3a-no-http-to-file-access` (§3a)
[2] CWE-912
[3] OWASP:A08
