---
type: Guard
title: "go-tls-verify-disabled"
description: "TLS certificate verification disabled (InsecureSkipVerify: true)."
timestamp: "2026-08-11T11:20:17+08:00"
guard_id: "go-tls-verify-disabled"
checklist_section: ["8"]
---

# TLS certificate verification disabled (InsecureSkipVerify: true)

_Author — Marconi, 2026-08-10_

---

## The threat

**CWE-295 (Improper Certificate Validation).** Go's `crypto/tls` package's `tls.Config`
struct has an `InsecureSkipVerify` field. Setting `InsecureSkipVerify: true` disables BOTH
certificate chain validation and hostname verification on every TLS connection that uses
that config. The client now trusts whatever server answers the connection — it never checks
that the presented certificate chains to a trusted root, and never checks that the
certificate's name matches the host it dialed.

- **WHO reaches it:** any network-positioned attacker able to intercept traffic between the
  Go process and the server it's dialing — a compromised router, a rogue Wi-Fi AP, a
  malicious or coerced proxy, or an attacker with DNS-spoofing capability on that path.
- **WITH WHAT PRIVILEGE:** none beyond network position. No credential or prior access to
  either endpoint is required.
- **TO WHAT EFFECT:** full man-in-the-middle — the attacker can read and modify every byte
  of the "TLS-protected" connection undetected. If the connection carries credentials, API
  tokens, or sensitive data, those are exposed; if it carries commands or responses the app
  trusts, those can be tampered with.

This is the Go-language counterpart to `tls-verify-disabled` (`requests.get(url,
verify=False)` / `httpx.Client(verify=False)` on the Python side) — same underlying failure
mode (a client-side TLS verification bypass), different language's idiom for reaching it.

## Why it's often introduced

A developer hits a certificate error while testing against a local server, a self-signed
cert, or a staging environment with an untrusted CA, and reaches for `InsecureSkipVerify` as
the fastest way past the error:

```go
// added to get past a local dev cert error, never removed
cfg := &tls.Config{InsecureSkipVerify: true}
client := &http.Client{Transport: &http.Transport{TLSClientConfig: cfg}}
```

Because it's a single field on a struct literal (or one assignment line on an existing
`*tls.Config`), it's trivial to add and easy to forget to remove before the code ships. It
is also a common copy-paste from Stack Overflow answers and outdated tutorials that suggest
it as a quick fix for "x509: certificate signed by unknown authority" without mentioning the
tradeoff.

## Detection design

1. **`applies()` gate** — `"go" in profile.features`. Fires only on repos where Go source
   was actually detected (mirrors `hardcoded-llm-provider-key`'s Go pass and the
   `applies()` convention of every other stack-scoped guard).
2. **Files scanned** — every `.go` file under the detected Go dirs
   (`go_scan_dirs(root, profile)`), via `iter_files(d, (".go",))`. No non-product path
   filtering: unlike a credential, a live TLS-verification bypass in test/fixture Go code is
   still worth flagging if it's the kind of pattern a developer might copy into production
   code, and — more importantly — this guard has no path-based FP class the way secret
   guards do (a test fixture "pretending" to have a fake key is a real category; a test
   fixture "pretending" to disable cert verification usually just... disables it in that
   test, same signal).
3. **Pattern** — two independent regexes, either one fires:
   - **Struct-literal form**: `InsecureSkipVerify\s*:\s*true` — matches
     `InsecureSkipVerify: true` and the no-space `InsecureSkipVerify:true` variant, the
     idiom used when constructing a `tls.Config{...}` composite literal.
   - **Field-assignment form**: `InsecureSkipVerify\s*=\s*true` — matches
     `cfg.InsecureSkipVerify = true`, the idiom used when mutating an already-constructed
     `*tls.Config` value. The two regexes never both match the same occurrence: Go struct
     literals use `:` and assignment statements use `=`, so the colon/equals split is the
     natural disambiguator between "constructing" and "mutating."

   Both regexes are applied to `strip_go_comments(read(f))` — the same lexer used by
   `hardcoded_llm_provider_key.py`'s `_scan_go`, string/rune/raw-string-aware so a match
   inside a Go string literal (documentation, a log message) does not fire on the raw text
   before stripping, and comment text does not fire either since it's blanked. Line numbers
   are preserved by `strip_go_comments`, so a match's line is reported by its exact original
   physical line number, matching the pragma below (checked against the comment-only view of
   the same line).
4. **Inline opt-out** — a `// security: allow-go-tls-verify-disabled` comment, checked
   against the COMMENT-ONLY view of the line (`comment_view(…, "go")`, #424): the pragma is
   itself a `//` comment, which `strip_go_comments` would blank before a check against the
   stripped copy ever saw it, and a string literal quoting the phrase must not count (same
   reasoning, same code shape, as `hardcoded_llm_provider_key.py`'s `_GO_PRAGMA` check).
5. **Severity / rule / standards** — HIGH for both forms (each pattern IS the vulnerability
   once present, not just a signal of one). Rule id:
   `go-tls-verify-disabled/insecure-skip-verify` — a single rule id for both forms, since
   they express the same underlying config state (`InsecureSkipVerify == true`) via two
   different Go syntaxes, not two different vulnerability classes. Standards: `["CWE-295"]`
   (same standard as the Python sibling `tls-verify-disabled`).

## When NOT to flag

**The scoping decision — bare field-name match, no `tls.Config{` proximity requirement.**
This guard deliberately does NOT anchor the match to appearing near a `tls.Config{` token.
The reasoning:

- `InsecureSkipVerify` is not a generic English word or a common config-flag name — it is
  the literal, specific name Go's standard library gives to exactly one field, on exactly
  one struct (`crypto/tls.Config`), with exactly one well-documented, security-relevant
  meaning. No other stdlib struct and no widely-used third-party struct this reviewer is
  aware of independently reuses that exact identifier for an unrelated purpose — unlike
  `.verify` (the Python sibling's overloaded attribute name, which really does collide with
  JWT decoders and schema validators, hence that guard's `_HTTP_CUE`-scoped loose form).
- **The genuine edge case** — a user's OWN struct type declares its own field also named
  `InsecureSkipVerify` (e.g. a config wrapper: `type MyTLSOpts struct { InsecureSkipVerify
  bool }`) — was considered and deliberately accepted rather than excluded:
  - If that field is ever forwarded into a real `tls.Config.InsecureSkipVerify` (which is
    the overwhelmingly likely reason a developer would choose that exact name instead of
    something like `SkipTLSVerify` or `AllowInsecure`), the underlying risk is identical —
    scoping to `tls.Config{` proximity would make the guard blind to the wrapper case, which
    is arguably the WORSE of the two since it's one level of indirection further from an
    obvious "this is a TLS setting" read.
  - If that field name is chosen for something else entirely, it is a confusing and
    actively misleading naming choice — a reviewer skimming the code would make the exact
    same "this disables TLS verification" assumption the guard does. A guard flagging a
    misleadingly-named field is a legitimate, actionable finding (rename the field), not a
    pure false positive.
  - Requiring textual proximity to `tls.Config{` would also make the struct-literal form
    brittle against a config assembled across many lines, built via a helper function, or
    constructed through a composite literal passed as a function argument — all common real
    Go idioms where `tls.Config{` and `InsecureSkipVerify:` don't sit inside any fixed-size
    textual window together.
- `InsecureSkipVerify: false` (or omitted entirely, the zero-value default) — the safe,
  common case; neither regex matches `false`.
- A mention only inside a `//` comment (documenting the anti-pattern, a TODO, a code-review
  note) — comments are blanked by `strip_go_comments` before the pattern check runs.
- An audited case, suppressed with `// security: allow-go-tls-verify-disabled` on the
  offending line.

## Tests

| Test | What it checks |
|---|---|
| `test_go_tls_verify_disabled_fires_on_struct_literal` | Positive: `tls.Config{InsecureSkipVerify: true}` inline in an `http.Transport{TLSClientConfig: ...}` construction fires HIGH (**verified_by**). |
| `test_go_tls_verify_disabled_fires_on_field_assignment` | Positive: `cfg.InsecureSkipVerify = true` post-construction assignment also fires. |
| `test_go_tls_verify_disabled_silent_on_false` | FP-bait: `InsecureSkipVerify: false` → silent. |
| `test_go_tls_verify_disabled_silent_on_empty_config` | FP-bait: a `tls.Config{}` with no mention of `InsecureSkipVerify` at all → silent. |
| `test_go_tls_verify_disabled_silent_on_comment_only` | FP-bait: the pattern appearing only inside a `//` comment → silent. |
| `test_go_tls_verify_disabled_pragma_silences` | Suppress pragma on the offending line → silent. |
| `test_go_tls_verify_disabled_not_applies_without_go` | `applies()` gate false without `go` in `profile.features`. |
| `test_go_tls_verify_disabled_applies_with_go` | `applies()` gate true with `go` in `profile.features`. |

## Known bypasses

- **Indirection via a variable/constant**: `skip := true; cfg := &tls.Config{InsecureSkipVerify:
  skip}` — the guard matches the literal token `true` directly after the field, not a
  variable or constant resolving to it at runtime.
- **Multi-line struct literals where the field sits alone on its own line with a trailing
  comma and the value on a different line** — not a realistic Go formatting pattern (`gofmt`
  keeps `Field: value` together), but any construction that splits the field name and the
  literal `true` across two physical lines would evade the same-line regex.
- **Reflection or dynamic field-setting** (`reflect.ValueOf(cfg).Elem().FieldByName(...)`) —
  vanishingly rare for this specific field in real code, and not matched since there is no
  literal `InsecureSkipVerify` token adjacent to `true` at all.
- **A build-tag-gated file** where the guard has no notion of Go build constraints — a file
  behind `//go:build integration` still gets scanned and flagged even if it never compiles
  into the production binary.

## What this guard does NOT prove

A silent guard does not mean TLS is correctly verified everywhere in the Go codebase. It
does not check: a custom `VerifyPeerCertificate`/`VerifyConnection` callback that
independently reintroduces a verification bypass while leaving `InsecureSkipVerify` at its
safe default; a `tls.Config` constructed and mutated across multiple files where the literal
`true` never appears adjacent to the field name in the same physical line; TLS verification
disabled at a layer below `crypto/tls` (a custom `net.Conn` wrapper, a non-stdlib TLS
library); or a `GODEBUG`/environment-variable-driven runtime override. It is a narrow,
high-confidence signal for the exact two textual idioms Go code uses to set this one field,
adapted from this project's existing Python `tls-verify-disabled` guard to Go's real syntax.

# Citations

[1] agentsec checklist item `8-tls-verify-disabled` (§8)
