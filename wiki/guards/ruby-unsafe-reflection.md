---
type: Guard
title: "ruby-unsafe-reflection"
description: "No dynamic Ruby class reflection (constantize/const_get) driven by a non-literal, attacker-influenceable name."
timestamp: "2026-09-11T00:00:00Z"
guard_id: "ruby-unsafe-reflection"
checklist_section: ["3b"]
standards: ["OWASP:A01"]
---

# Unsafe dynamic class reflection (Ruby)

Flags Ruby constant lookups whose class name is not a static literal. Extends checklist item
`3b-dynamic-import-non-literal` — the Ruby counterpart to the existing `dynamic-import-non-literal`
(Python) guard, widening the same item rather than duplicating it, because the requirement is
identical ("an attacker-influenceable string must never choose which code loads") and only the
mechanism differs (Ruby constant lookup vs. Python module import). OWASP:A01 (Broken Access
Control), CWE-706 (Use of Incorrectly-Resolved Name or Reference).

## The threat

`params[:type].constantize.new` — the request decides *which class* the application instantiates.
Every constant already loaded into the Ruby VM is reachable: another model (`User`, so an
`.new`/`.find` on data the caller should never touch), a service object whose initializer has side
effects, a class whose `inherited`/`const_missing` hooks run on reference. This is the
class-pollution / arbitrary-object-instantiation primitive, and in a Rails app with eager loading
the reachable set is the entire application plus every gem.

`"User".constantize` is the *same method* and is completely safe. The vulnerability is the
argument's provenance, not the call.

## Exploitability rationale

HIGH. Not automatic RCE on its own — it gives the attacker a *choice of class*, and what that buys
depends on which classes are loaded — but it is a direct, unauthenticated reach into code paths
the route never intended, it composes with almost any gadget class in the dependency tree, and it
is trivially reachable (one request parameter). Likelihood is high because the idiom reads as
elegant Rails: `params[:type].constantize` is shorter than the `Hash` lookup that would be correct,
so it is written on purpose, not by accident.

## What counts as a hit (and what doesn't)

- **`.constantize` / `.safe_constantize`** — the *receiver* carries the class name. Fires unless
  that receiver is entirely one plain quoted string literal. `safe_constantize` returns `nil`
  instead of raising, which changes the failure mode and not the danger, so it is treated
  identically.
- **`.const_get` / `.qualified_const_get`** — the *first argument* carries the class name. Fires
  unless that argument is entirely one string literal or one symbol literal (`:User`). Both the
  parenthesised and Ruby's paren-less call forms are read.
- **Interpolation and concatenation are hits**, even with a literal prefix:
  `"#{params[:ns]}::Handler".constantize` and `Object.const_get("App::" + kind)` both fire — a
  fixed namespace prefix does not bound which constant is reached (`"App::" + "../"`-style
  namespace escapes aside, the suffix alone is enough to pick any class in that namespace).
- **A method definition is not a call.** A line beginning `def ` is skipped, so a library that
  defines its own `self.constantize(name)` helper does not fire on its own definition.
- **`deconstantize`** (ActiveSupport's string-trimming method) is a different method and does not
  fire.

## When NOT to flag (and the pragma)

- `"User".constantize` / `'Billing::Invoice'.safe_constantize` → silent (a static literal).
- `Object.const_get("Widget")` / `Object.const_get(:User)` → silent (string or symbol literal).
- The remediation shape — an allowlist `Hash` mapping permitted names to classes, resolved with
  `fetch` — contains no reflection at all and is silent.
- Commented out (`#` or a real `=begin`/`=end` block) → silent; comment stripping is string-aware,
  so a `#` inside a genuine string literal on the same line is not mistaken for a comment start.
- Spec/test trees (`spec/`, `test/`, `fixtures/`, …) are out of scope: resolving a class name
  from a variable is ordinary, intentional code in factories, shared examples and
  `described_class` metaprogramming. Same call as the Python sibling this guard is the
  counterpart to (`dynamic-import-non-literal`) and as `ruby-dangerous-dispatch`, which scopes
  out the identical RSpec shape.
- A name already validated against an allowlist upstream → suppress explicitly:

```ruby
klass = type_name.constantize  # security: allow-unsafe-reflection
```

## Known bypasses (honest limits)

- **No dataflow.** The guard proves the name is *non-literal*, not that it is *attacker-reachable*.
  A `constantize` on a constant read from a trusted config file fires exactly as loudly as one on
  `params` — the pragma is the intended correction, not a limitation to fix later. The trade is
  deliberate and matches the Python sibling: proving reachability needs a dataflow engine this
  zero-dependency guard does not have, and the false-negative cost of guessing wrong is a
  class-instantiation primitive.
- **Single-line, textual.** A receiver built across several lines
  (`name = "App::"\nname += kind\nname.constantize`) fires on the `constantize` line (the receiver
  is a bare variable, so this is the correct verdict), but a call split across a line continuation
  — `foo\n  .constantize` — is read as a bare `.constantize` with an empty receiver prefix and also
  fires. Both land on the safe side; neither is a *miss*.
- **Paren-less `const_get` with a trailing modifier over-fires.** `Object.const_get "Widget" if x`
  reads the argument as `"Widget" if x`, which is not entirely a literal, so it fires. Rare shape;
  documented rather than silently assumed away, and the pragma clears it.
- **Percent-literals and heredocs are not string-aware.** Inherited from `strip_ruby_comments`,
  which deliberately does not track `%q()`/`%w[]`/`<<~TEXT` forms. A `constantize` mention inside a
  heredoc body could false-fire.
- **`Kernel#eval`, `Object#send`, `Marshal.load`** are adjacent dynamic-dispatch primitives with the
  same "attacker picks the code" shape and are **not** covered here — they are separate checks.

## What this guard does NOT prove

A clean scan means no non-literal `constantize`/`const_get` call-site was found in the scanned Ruby
source. It says nothing about a class resolved through `Object.const_missing`, `send`, `eval`, a
gem that wraps reflection behind its own API, or a name deserialized from YAML/Marshal — all of
which reach the same primitive by a route this guard does not read.

## Canary plant

`reflection.rb` — `klass = params[:type].constantize` inside a controller action, no pragma.
Expected rule: `ruby-unsafe-reflection/non-literal-class-name`.

# Examples

```ruby
# FIRES — a request parameter picks which class is instantiated.
class WidgetsController < ApplicationController
  def create
    klass = params[:type].constantize
    render json: klass.new
  end
end

# FIRES — interpolation, and a fixed prefix does not bound the reachable set.
handler = "#{params[:ns]}::Handler".constantize

# FIRES — const_get's ARGUMENT is the name; a literal prefix buys nothing.
Object.const_get("App::" + kind)

# SILENT — static literals, whether string or symbol.
klass = "User".constantize
Object.const_get(:User)

# SILENT — the fix: an allowlist, no reflection at all.
EXPORTERS = { 'csv' => CsvExporter, 'pdf' => PdfExporter }.freeze
EXPORTERS.fetch(params[:kind]) { raise ArgumentError, 'unknown exporter' }
```

# Citations

[1] agentsec checklist item `3b-dynamic-import-non-literal` (§3b)
[2] OWASP:A01 (Broken Access Control)
[3] CWE-706 (Use of Incorrectly-Resolved Name or Reference)
[4] Brakeman, `lib/brakeman/checks/check_unsafe_reflection.rb` (`Brakeman::CheckUnsafeReflection`)
    — pattern provenance only; detection logic and fixtures here are original
