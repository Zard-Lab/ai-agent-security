---
type: Guard
title: "ruby-unsafe-deserialization"
description: "No unsafe deserialization of untrusted data (Marshal / YAML.load / Oj object mode) in Ruby code."
timestamp: "2026-09-11T00:00:00Z"
guard_id: "ruby-unsafe-deserialization"
checklist_section: ["3b"]
standards: ["OWASP:A08"]
---

# No unsafe deserialization of untrusted data (Ruby)

Flags Ruby deserialization sinks that execute the payload while loading it: `Marshal.load`/
`Marshal.restore`, Psych's unsafe `YAML.load`/`Psych.load`, and the `Oj` gem's object mode.
Extends checklist item `3b-unsafe-deserialization` — the Ruby counterpart to the existing
`unsafe-deserialization` guard (Python `pickle`/`torch.load`/`yaml.load`, JS `js-yaml` unsafe
schemas), widening the same item rather than duplicating it (part of agentsec's Ruby guard
family). OWASP:A08 (Software and Data Integrity Failures), CWE-502.

## The threat

`Marshal.load(blob)` reconstructs a Ruby object graph by instantiating the classes named in the
serialized bytes and running their deserialization hooks. An attacker who controls those bytes
controls which classes are built and which hooks run — a gadget chain ends in arbitrary command
execution. It is the exact analogue of Python's `pickle.loads`, and it appears wherever a Ruby app
round-trips objects through a cookie, a cache entry, a job queue payload, or a file upload.

`YAML.load(doc)` is the same hazard in a format that looks like configuration. Psych's unsafe
loader honors `!ruby/object:` tags, so a crafted document instantiates arbitrary Ruby objects as
it parses — the mechanism behind the Rails YAML deserialization RCEs (CVE-2013-0156 and
successors). `Oj.object_load` / `Oj.load(..., mode: :object)` is the same sink again under a JSON
parser's name: Oj's object mode reads `^o`/`^u` type keys and rebuilds arbitrary Ruby objects
rather than returning plain data.

## Exploitability rationale

CRITICAL. On attacker-reachable bytes every one of these is direct remote code execution, not a
weakening of a control: a single load call is the whole exploit, and public gadget chains for
stock Rails/ActiveSupport class sets have existed for years. Likelihood is high because the unsafe
API is the *shorter* name in every case — `Marshal.load` over a JSON round-trip, `YAML.load` over
`YAML.safe_load`, `Oj.load` over an explicit strict mode — so the dangerous call is what a
developer reaches for first.

## What counts as a hit (and what doesn't)

- **`Marshal.load(...)` / `Marshal.restore(...)`** fire, with either separator (`Marshal::load`
  is legal Ruby and still appears in older code). `Marshal.dump(...)` never fires: serialization
  is not a sink.
- **`YAML.load(...)` / `Psych.load(...)`** fire. `YAML.safe_load(...)` does not — it is the fix,
  and the pattern requires `load` to follow the separator immediately, so neither `safe_load` nor
  `load_file` can match it.
- **`Oj.object_load(...)`** fires unconditionally (a dedicated object-mode entry point).
  **`Oj.load(...)`** fires only when an explicit object mode is written in the same call line
  (`mode: :object` or `:mode => :object`).
- Every hit is one finding per line, rule-tagged by family:
  `ruby-unsafe-deserialization/marshal-load`, `/yaml-unsafe-load`, `/oj-object-mode-load`.
- Ruby's `Marshal`/`Psych` APIs have no "declared non-security use" opt-out the way Python's
  `hashlib(usedforsecurity=False)` does — the pragma below is the only escape hatch.

## When NOT to flag (and the pragma)

- `YAML.safe_load(doc, permitted_classes: [Date])` → silent (the fix).
- `Marshal.dump(obj)` → silent.
- **`Marshal.load(Marshal.dump(obj))` → silent.** This is the canonical Ruby deep-copy one-liner;
  the bytes are produced and consumed inside the same expression and never leave the process, so
  there is no untrusted input to attack with. Only the single-expression form is exempted — a dump
  whose result travels through a variable, a cache, or another process is not this idiom and still
  fires (pinned by test in both directions).
- **A bare `Oj.load(data)` → silent.** Its effective mode comes from `Oj.default_options`, which
  may be set in an initializer far from the call site; resolving it needs dataflow this guard does
  not do, and `Oj.load` against a `:strict`/`:compat` default is ordinary, safe JSON parsing that
  appears in a great deal of real Ruby code. Flagging it would be a high-volume false positive on
  Oj's most common call shape. **Disclosed false negative:** an app that sets
  `Oj.default_options = {mode: :object}` globally and then calls a bare `Oj.load` on untrusted
  JSON is not detected.
- **`YAML.load_file(path)` → silent.** Loading a repo-local config file is the dominant real use
  of that API, so it is deliberately outside the pattern. **Disclosed false negative:**
  `YAML.load_file(user_supplied_path)` is not detected.
- Commented out (`# Marshal.load(...)`) → silent; comment stripping is string-aware, so a `#`
  inside a genuine string literal on the same line is not mistaken for a comment start. A real
  `=begin`/`=end` block comment mentioning the pattern → silent.
- An audited trusted-source load → suppress explicitly:

```ruby
Marshal.load(cache_blob)  # security: allow-ruby-unsafe-deserialize
```

## Known bypasses (honest limits)

- **No dataflow, no taint.** The guard fires on the call site, with no attempt to prove the bytes
  are attacker-reachable. A `Marshal.load` of an internally produced blob fires CRITICAL just as
  loudly as one over a request body — the pragma is the intended correction, not a limitation to
  fix later. Conversely, a sink reached through indirection (`loader = Marshal.method(:load)`, a
  `send(:load, ...)`, an aliased constant) is not traced.
- **Same-line only for the Oj mode argument.** `Oj.load(body,\n  mode: :object\n)` written across
  lines is not detected, because the mode test runs against the line holding the call.
- **String contents are not blanked.** `strip_ruby_comments` blanks comments, not string literals,
  so a complete call shape written *inside* a string (`logger.warn("never use Marshal.load(x)")`)
  false-fires. Measured in the adversarial self-test and left as-is rather than papered over: the
  sibling `ruby-weak-crypto` has the identical limit, and fixing it belongs in the shared helper,
  not here.
- **`%w[]`/heredoc-embedded mentions are not comment/string-aware.** `strip_ruby_comments`
  deliberately does not track Ruby's percent-literal or heredoc string forms — a call shape inside
  a heredoc body is not recognized as "inside a string". Documented rather than silently assumed
  away.
- **Other CWE-502 sinks in Ruby are out of scope**, notably `CSV.load` (removed in newer Ruby) and
  gem-specific loaders that wrap `Marshal` internally.

## What this guard does NOT prove

A clean scan means no in-scope deserialization call site was found in the scanned Ruby source. It
says nothing about a `Marshal.load` reached inside a gem the app depends on (Rails' own cookie
store and `ActiveSupport::Cache` both marshal by default), a payload deserialized by a background-
job backend's configured serializer, or any of the disclosed false-negative shapes above.

## Canary plant

`session_store.rb` — `Marshal.load(blob)` inside a method body, no pragma, argument is not a
`Marshal.dump(...)` call. Expected rule: `ruby-unsafe-deserialization/marshal-load`.

# Citations

[1] agentsec checklist item `3b-unsafe-deserialization` (§3b)
[2] OWASP:A08 (Software and Data Integrity Failures)
[3] CWE-502 (Deserialization of Untrusted Data)
[4] Brakeman, `lib/brakeman/checks/check_deserialize.rb` (`Brakeman::CheckDeserialize`) — the
    sink inventory this guard's pattern was verified against; detection logic here is original
[5] CVE-2013-0156 — Rails YAML/`!ruby/object:` deserialization remote code execution
