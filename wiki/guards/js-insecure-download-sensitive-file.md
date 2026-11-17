---
type: Guard
title: "js-insecure-download-sensitive-file"
description: "HTTP/FTP download URL for an executable or other sensitive file type."
timestamp: "2026-07-14T10:59:45+08:00"
guard_id: "js-insecure-download-sensitive-file"
checklist_section: ["5"]
standards: ["OWASP:A08"]
---

# HTTP/FTP download URL for an executable or other sensitive file type

_Author — 2026-07-14_

---

## The threat

A literal `http://` or `ftp://` URL (not HTTPS) whose path ends in a dangerous file
extension — an executable, archive, or script — is a man-in-the-middle target: an
attacker on-path (rogue Wi-Fi, a compromised jump host, a TLS-intercepting proxy)
can substitute the downloaded file with malicious content before it reaches the
client. CWE-829, OWASP:A08.

## Why this guard fits the stack

New checklist item — agentsec had no "insecure download" concept before this. The
existing supply-chain guards (`js-supply-chain`/`python-supply-chain`) check
dependency manifests and lockfiles for known-vulnerable packages; this guard checks
a completely different surface — a literal download URL hardcoded in application
code, regardless of any package manager. Sourced from GitHub CodeQL's
`js/insecure-download` query (`InsecureDownloadQuery.ql` + `Customizations.qll`,
verified against real fetched source) — the dangerous-extension list is copied
verbatim from upstream's `unsafeExtension()` predicate.

## Detection design

1. `applies()` gates on `"javascript"`/`"typescript"` language presence.
2. Scans `.js`/`.jsx`/`.ts`/`.tsx` files, skipping non-product paths.
3. Skips whole-line `//` comments and any line containing the pragma.
4. A single, self-contained regex: a quoted `http://`/`ftp://` URL literal ending in
   one of the dangerous extensions (`exe`/`dmg`/`pkg`/`tar.gz`/`zip`/`sh`/`bat`/
   `cmd`/`app`/`apk`/`msi`/`js`/`py`/`jar`/`war`). No call-context requirement —
   unlike the other two guards in this batch, the URL literal itself (insecure
   scheme + dangerous extension) is already a strong, self-contained signal
   regardless of which function ultimately consumes it, so no windowing is needed
   at all (and therefore no risk of the multi-line bleed-through class the
   `js-system-prompt-injection` guard in this same batch hit and fixed).
5. Fires HIGH, once per file, rule
   `js-insecure-download-sensitive-file/http-ftp-sensitive-extension`,
   `["OWASP:A08", "CWE-829"]`.
6. Inline opt-out: `# security: allow-js-insecure-download-sensitive-file`.

## When NOT to flag

An HTTPS URL with the same extension does not fire (verified: the regex requires
the literal `http://`/`ftp://` scheme prefix, which cannot match inside `https://`
since the character immediately after `http` in an HTTPS URL is `s`, not `:`). An
HTTP URL with a non-dangerous extension (`.html`, `.json`, `.css`, ...) does not
fire.

## Tests

| Test | What it checks |
|---|---|
| `test_flags_http_exe_download` | Planted violation: `http://.../installer.exe` — fires |
| `test_flags_ftp_zip_download` | Planted violation: `ftp://.../bundle.zip` — fires |
| `test_silent_on_https_download` | FP-bait: the same path over HTTPS — silent |
| `test_silent_on_http_url_without_sensitive_extension` | FP-bait: an HTTP URL ending in `.html` — silent |
| `test_silent_on_comment_mentioning_pattern` | FP-bait: a doc comment describing the anti-pattern — silent |
| `test_pragma_suppresses` | Inline pragma silences the file |
| `test_not_applies_without_js_or_ts` | `applies()` is `False` without JS/TS |
| `test_nonproduct_path_skipped` | A file under `examples/` is skipped |

## Known bypasses

A URL assembled at runtime from string concatenation or a template literal with a
variable segment (`` `http://cdn.example.com/${file}` ``) is not resolved
statically and would not fire if the dangerous extension isn't a literal part of
the string.

## What this guard does NOT prove

Absence of a finding does not prove no insecure download exists — only a literal,
complete URL string with an explicit dangerous extension is checked. A URL built
dynamically, or one whose extension is determined at runtime, is outside this
guard's fixed pattern.

**Known limitations (fixed, review #395):** a trailing `?query`/`#fragment` after the extension
(`"http://cdn/installer.exe?v=2"`, `.tar.gz#sig`) previously bypassed the pattern, which required
the extension immediately before the closing quote — now optional. Comment stripping was
whole-line-`//`-only (a `/* */` block comment survived) — now uses the shared, string/regex-aware
`strip_js_comments()` helper.

# Citations

[1] agentsec checklist item `5-js-insecure-download-sensitive-file` (§5)
[2] OWASP:A08
