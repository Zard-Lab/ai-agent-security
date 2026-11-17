---
type: Guard
title: "ruby-tls-verify-disabled"
description: "TLS certificate verification disabled in Ruby HTTP/OpenSSL clients via OpenSSL::SSL::VERIFY_NONE."
timestamp: "2026-09-11T00:00:00Z"
guard_id: "ruby-tls-verify-disabled"
checklist_section: ["8"]
standards: ["CWE-295"]
---

# TLS certificate verification disabled (Ruby)

Flags `OpenSSL::SSL::VERIFY_NONE` reaching a `verify_mode` slot in Ruby source. Extends checklist
item `8-tls-verify-disabled` — the Ruby counterpart to the existing `tls-verify-disabled`
(Python/Express) and `go-tls-verify-disabled` (Go) guards, widening the same item rather than
duplicating it (Ruby guard batch). CWE-295 (Improper Certificate Validation).

## The threat

```ruby
http = Net::HTTP.new(uri.host, uri.port)
http.use_ssl = true
http.verify_mode = OpenSSL::SSL::VERIFY_NONE
```

`OpenSSL::SSL::VERIFY_NONE` tells OpenSSL to accept whatever certificate the peer presents — or
none at all. The connection is still *encrypted*, which is what makes this so easy to leave in:
it looks like working HTTPS. But nothing checks that the peer is the intended host, and nothing
checks that its certificate chains to a trusted root, so a man-in-the-middle anywhere on the
network path can present their own certificate, terminate the TLS session, and read and rewrite
every request and response undetected. The encryption protects the traffic from a passive
eavesdropper only.

This is the classic "I'll fix the cert error later" shortcut, usually left over from a local
self-signed-certificate debugging session, and once set it silently defeats TLS on every
subsequent request through that client or context.

## Exploitability rationale

HIGH — matching the Python and Go siblings for the same defect. It is not a one-shot RCE, but it
voids a security control the whole rest of the system trusts: credentials in an `Authorization`
header, an API response the app treats as authoritative, an OAuth token exchange. Exploitation
needs network position (hostile Wi-Fi, a compromised hop, a rogue egress proxy, DNS poisoning),
which is a real and routinely-available capability, not a theoretical one.

## What counts as a hit (and what doesn't)

The detection is anchored on the *slot* (a `verify_mode` key) receiving the *fully-qualified
constant* (`OpenSSL::SSL::VERIFY_NONE`, optionally with a leading `::` scope operator). All three
shapes real Ruby code writes it in fire:

- **Receiver-attribute assignment** — `http.verify_mode = OpenSSL::SSL::VERIFY_NONE`, the
  `Net::HTTP` instance setter. The most common shape in real Ruby applications; `@http.`,
  `ctx.`, and any other receiver work the same way.
- **Bare assignment** — `verify_mode = OpenSSL::SSL::VERIFY_NONE`, e.g. inside an
  `OpenSSL::SSL::SSLContext.new.tap { |ctx| ... }` block or a configuration builder.
- **Keyword-argument / hash form** — `Net::HTTP.start(host, port, use_ssl: true, verify_mode:
  OpenSSL::SSL::VERIFY_NONE)`, the older `:verify_mode => ...` hash-rocket spelling, and the
  Rails ActionMailer variant `smtp_settings = { openssl_verify_mode: OpenSSL::SSL::VERIFY_NONE }`
  (an underscore-prefixed key such as `openssl_verify_mode`/`ssl_verify_mode` names the same
  OpenSSL setting, so it fires too).

Because the match is anchored on the `verify_mode` slot and not on a nearby `Net::HTTP.start(`
token, a long call wrapped across several lines — the kwarg sitting on its own line, far from its
receiver — still fires, and the finding is reported on the line that actually sets the value.

## When NOT to flag (and the pragma)

- `verify_mode = OpenSSL::SSL::VERIFY_PEER` → silent. That is the fix, in both the assignment
  and the keyword forms.
- A **comparison** against the constant → silent. `raise 'insecure' if ctx.verify_mode ==
  OpenSSL::SSL::VERIFY_NONE` is code *checking* that verification is not disabled — a security
  control, the opposite of a violation. The operator alternation accepts `=`, `=>` and `:` but
  never `==` or `=~`.
- An unrelated `verify_mode` attribute on a non-OpenSSL object (`signature.verify_mode = :strict`,
  `token.verify_mode = ENV['JWT_VERIFY_MODE']`) → silent; the right-hand side is anchored to the
  fully-qualified OpenSSL constant, so a `verify_mode` name alone is never enough to fire.
- Commented out (`# http.verify_mode = OpenSSL::SSL::VERIFY_NONE`) → silent; comment stripping is
  string-aware, so a `#` inside a genuine string literal on the same line is not mistaken for a
  comment start.
- A real Ruby `=begin`/`=end` block comment mentioning the pattern → silent.
- An audited case a real app genuinely cannot avoid yet → suppress explicitly:

```ruby
http.verify_mode = OpenSSL::SSL::VERIFY_NONE  # security: allow-ruby-tls-verify-disabled
```

The pragma is checked against the **comment-only view** of the line (#424) — the pragma *is* a
comment, so a check against the stripped copy would always miss it.

## Known bypasses (honest limits)

- **No dataflow.** `mode = OpenSSL::SSL::VERIFY_NONE` on one line and `http.verify_mode = mode`
  on the next is not traced — neither line matches the slot-plus-constant shape. Same textual
  scope as the Python and Go siblings, which likewise do not follow a value through a variable.
- **The constant must be written fully-qualified on the same line as the slot.** A file that does
  `include OpenSSL::SSL` and then writes a bare `verify_mode = VERIFY_NONE`, or that splits the
  assignment across a line break (`http.verify_mode =` / newline / `  OpenSSL::SSL::VERIFY_NONE`),
  is missed. Both are rare in practice; requiring the qualified constant is what keeps the guard
  from firing on every unrelated `verify_mode` attribute in the codebase.
- **A gem that disables verification internally is invisible.** An HTTP wrapper gem configured
  with its own `verify: false`-style option (Faraday's `ssl: { verify: false }`, HTTParty's
  `verify: false`) reaches the same outcome by a different spelling and is not covered by this
  guard.
- **String bodies are not blanked.** `strip_ruby_comments` blanks comments, not string contents,
  so the pattern written inside a string literal (a log message quoting the bad config verbatim)
  can false-fire. Verified in the adversarial self-test and documented rather than silently
  assumed away; the same tolerance every sibling guard carries, and the pragma is the correction.
- **`%w[]`/heredoc-embedded mentions are not comment/string-aware** — `strip_ruby_comments`
  deliberately does not track Ruby's percent-literal or heredoc string forms.

## What this guard does NOT prove

A clean scan means no `verify_mode`-set-to-`VERIFY_NONE` call site was found in the scanned Ruby
source. It says nothing about verification disabled through a gem's own option, through an
environment variable read at runtime, through a system-wide OpenSSL configuration file, or in a
native extension that never goes through Ruby's `OpenSSL::SSL` constants.

## Canary plant

`ruby_http_client.rb` — a `Net::HTTP` client with `http.use_ssl = true` followed by
`http.verify_mode = OpenSSL::SSL::VERIFY_NONE`, no pragma. Expected rule:
`ruby-tls-verify-disabled/verify-mode-none`.

# Examples

Vulnerable — the receiver-attribute form (fires):

```ruby
require 'net/http'

def fetch(uri)
  http = Net::HTTP.new(uri.host, uri.port)
  http.use_ssl = true
  http.verify_mode = OpenSSL::SSL::VERIFY_NONE
  http.get(uri.path)
end
```

Vulnerable — the keyword-argument form (fires):

```ruby
Net::HTTP.start(host, port, use_ssl: true, verify_mode: OpenSSL::SSL::VERIFY_NONE) do |http|
  http.request(req)
end
```

Fixed — verify against the correct CA instead of turning verification off (silent):

```ruby
http = Net::HTTP.new(uri.host, uri.port)
http.use_ssl = true
http.verify_mode = OpenSSL::SSL::VERIFY_PEER
http.ca_file = '/etc/ssl/certs/internal-ca.pem'  # for a genuinely private CA
http.get(uri.path)
```

Not a violation — a defensive check that verification is on (silent):

```ruby
raise 'insecure TLS config' if ctx.verify_mode == OpenSSL::SSL::VERIFY_NONE
```

# Citations

[1] agentsec checklist item `8-tls-verify-disabled` (§8)
[2] CWE-295 (Improper Certificate Validation)
[3] Brakeman `lib/brakeman/checks/check_ssl_verify.rb`, `Brakeman::CheckSSLVerify` — pattern
    provenance only; detection logic here is original
[4] Ruby stdlib `OpenSSL::SSL::SSLContext#verify_mode` / `Net::HTTP#verify_mode`
[5] agentsec siblings `tls-verify-disabled` (Python/Express) and `go-tls-verify-disabled` (Go)
