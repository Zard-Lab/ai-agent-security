---
type: Guard
title: "java-ssrf"
description: "No server-side fetch from a tainted java.net.URL — the SSRF idiom new URL(input).openConnection()."
timestamp: "2026-09-12T00:00:00Z"
guard_id: "java-ssrf"
checklist_section: ["3a"]
standards: ["OWASP:A10", "ASVS:1.3.6"]
---

# No SSRF from a tainted java.net.URL

Flags the classic Java Server-Side Request Forgery idiom: a `java.net.URL` built from
non-literal input, then opened. Closes checklist item `3a-ssrf-general` — the Java counterpart to
the existing `ssrf-general` (Python) and `js-ssrf` (JS/Node) guards, extending the same checklist
item rather than duplicating it. OWASP:A10, ASVS:1.3.6, CWE-918.

## The threat

Server-Side Request Forgery: a server-side HTTP fetch whose URL is built from user/dynamic input
lets an attacker point it at internal services (`http://10.0.0.5/admin`) or the cloud metadata
endpoint (`http://169.254.169.254/latest/meta-data/iam/...`), turning the backend into a proxy for
reaching things the attacker can't reach directly. In Java, the idiom is `java.net.URL`:
construct one from an untrusted string, then call `.openConnection()`, `.openStream()`, or
`.getContent()` to actually issue the fetch.

## Exploitability rationale

HIGH. This is not a theoretical gadget — `new URL(...).openConnection()` is the standard-library
way to make an outbound HTTP request in Java with no framework in between, so it shows up directly
in application code (a webhook fetcher, an image-proxy endpoint, a URL-preview feature) with no
default steering toward an allow-list.

## What counts as a hit (and what doesn't)

- **`new URL(<non-literal>).openConnection()`** (or `.openStream()`/`.getContent()`), chained on
  one statement, fires. `new URL("https://api.example.com/status").openConnection()` — a pure
  string literal argument — does not.
- **`URL url = new URL(<non-literal>); ... url.openConnection();`** — built once, opened a few
  lines later — also fires, via a small forward line-window (see "Known bypasses"). A `URL`
  constructed and then only ever read (`url.toString()`, `url.getHost()`, never opened) does not
  fire — no fetch is actually issued.
- **"Non-literal"** means the argument is not a pure string literal, and not a `+`-concatenation of
  only string literals: a bare identifier (`new URL(target)`), a method call
  (`new URL(request.getParameter("url"))`), or a literal prefix concatenated with a variable
  (`new URL("https://" + host)`) all count. `new URL("https://" + "api.example.com")` — a
  concatenation of two literals, nothing dynamic — does not fire.

## When NOT to flag (and the pragma)

- A file on a non-product path (`is_nonproduct_path`) → silent. Maven and Gradle put test
  sources under `src/test/java`, whose `test` segment reads as non-product, alongside the shared
  `fixtures/`/`examples/` list and a repo's own configured `archive_segments`.
- A hardcoded literal URL, or a literal-only concatenation → silent (the fix, if the destination
  genuinely never varies).
- Commented out (`// new URL(target).openConnection()`) → silent; comment stripping is
  string-aware, so a `//`/`/*` inside a genuine string literal on the same line is not mistaken
  for a comment start.
- Inside a real `/** ... */` Javadoc block mentioning the pattern → silent.
- A deliberately audited internal fetch (e.g. behind an explicit allow-list this guard cannot
  verify) → suppress explicitly:

```java
new URL(target).openConnection(); // security: allow-java-ssrf
```

The pragma is read from the line's comment-only view (#424) — anywhere within the two-statement window (the
`new URL(...)` line through the line that actually opens it) silences the whole finding, so it can
be placed on either the construction line or the line that calls `.openConnection()`.

## Known bypasses (honest limits)

- **No dataflow, no allow-list awareness.** Like every sibling SSRF guard (`ssrf-general`,
  `js-ssrf`), this fires on the tainted-construction shape directly, with no attempt to prove an
  allow-list actually gates the fetch downstream. The pragma is the intended correction.
- **Textual, not a real parser.** Everything in agentsec is regex/text-block scanning (the
  zero-runtime-dependency constraint), so this is not a real AST or control-flow analysis.
- **The two-statement window is a fixed line count (6), not real dataflow.** A variable
  reassigned between the `new URL(...)` line and the `.openConnection()` call, or opened on a
  much later line/inside a different branch, is a known miss (false negative) or, less often, a
  false positive if the variable name is reused for something unrelated within the window.
- **`URI.create(...)`/`new URI(...)` and the wider `HttpClient`/`HttpURLConnection`/Apache
  `HttpClient.execute(new HttpGet(...))` shapes are deliberately out of scope for this guard.**
  Find Security Bugs' own `URLCONNECTION_SSRF_FD` sink list covers `java.net.URL` specifically;
  this guard follows that scope. A `URI` converted via `.toURL().openConnection()`, or an
  `HttpClient`/Apache-`HttpClient` request built from tainted input, is a real but currently
  undetected variant — tracked as a possible future guard extension, not silently assumed covered.
- **Multi-line argument construction is not traced.** An argument built across several statements
  before being passed into `new URL(...)` (e.g. a `StringBuilder`) is textually indistinguishable
  from a literal if the guard can't see the builder's inputs on the same line.

## What this guard does NOT prove

A clean scan means no tainted `new URL(...)` construction-then-open call-site was found in the
scanned Java source — it says nothing about a fetch issued via `URI`/`HttpClient`/a third-party
HTTP library, an allow-list that exists but doesn't actually cover the reachable input space, or a
URL received pre-validated from another service.

## Canary plant

`UrlFetcher.java` — `new URL(target).openConnection()` inside a method body, no pragma, no
allow-list. Expected rule: `java-ssrf/tainted-url-open-connection`.

# Citations

[1] agentsec checklist item `3a-ssrf-general` (§3a)
[2] OWASP:A10 (Server-Side Request Forgery)
[3] ASVS:1.3.6
[4] CWE-918 (Server-Side Request Forgery)
[5] Find Security Bugs — rule `URLCONNECTION_SSRF_FD`, sink list
    `injection-sinks/urlconnection-ssrf.txt` (provenance only; detection logic here is original)
