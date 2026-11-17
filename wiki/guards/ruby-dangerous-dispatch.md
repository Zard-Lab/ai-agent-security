---
type: Guard
title: "ruby-dangerous-dispatch"
description: "No dynamic method dispatch (send/__send__/public_send/try) with a non-literal, attacker-influenceable method name in Ruby."
timestamp: "2026-09-11T00:00:00Z"
guard_id: "ruby-dangerous-dispatch"
checklist_section: ["3b"]
standards: ["OWASP:A03", "CWE-470"]
---

# Dangerous dynamic method dispatch (Ruby)

Flags `Object#send` / `#__send__` / `#public_send` / Rails' `#try` called with a method name that
is not a static literal. Closes the new checklist item `3b-dynamic-method-dispatch` — the Ruby
counterpart in spirit to `dynamic-import-non-literal` (Python), but a genuinely new item: no
sibling in any language covers runtime method selection. OWASP:A03 (Injection), CWE-470 (Unsafe
Reflection). Second Ruby-language guard.

## The threat

```ruby
record.send(params[:action])
```

The receiver stays fixed; the *method* is chosen at runtime by the first argument. Whoever
controls that value chooses which of the receiver's methods runs. `send` and `__send__` go
further: they **bypass method visibility by design**, so the reachable set is not the object's
public API but every method it defines — `destroy!`, `update_column`, an internal
`assign_role`, a private credential reader. A single `send(params[:x])` in a controller turns an
object into an arbitrary-method-call gadget.

`public_send` respects visibility, which shrinks the blast radius but does not close it — the
public API of a typical ActiveRecord model already includes destructive methods. `try` is the
nil-safe Rails variant of the same mechanic and Brakeman's own `CheckSend` includes it for that
reason.

## Exploitability rationale

HIGH. Not automatically RCE, but it is a direct, single-hop escalation from "attacker supplies a
string" to "attacker names the method that runs on a live domain object", and the visibility
bypass means the surface is larger than anything the object's author intended to expose. The
pattern appears in exactly the place user input arrives — controller actions dispatching on a
`params[:action]`-style router key — and is trivially reachable with no chaining.

## What counts as a hit (and what doesn't)

- The call must have an **explicit receiver**: `obj.send(`, `obj&.send(`, `obj.__send__(`,
  `obj.public_send(`, `obj.try(`. The receiver-less `send(x)` form (implicit `self`) is out of
  scope — see known limits.
- The first argument is **safe only when it is entirely a plain literal**: a plain symbol
  (`:save`, `:save!`, `:valid?`, `:name=`) or a plain quoted string (`"save"` / `'save'`).
  Nothing else on either side of it.
- **Everything else fires**: a bare variable (`obj.send(meth)`), a constant (`obj.send(ACTION)`),
  a hash/params lookup (`obj.send(params[:action])`, `obj.public_send(h[:k])`), a method call
  (`obj.send(resolve_action(params))`), a ternary (`obj.send(ok ? :a : :b)`), an interpolated
  string (`obj.send("run_#{action}")`) and an interpolated symbol
  (`obj.public_send(:"#{action}")`) — a symbol *built* by interpolation is not a plain literal.
- Extra arguments after the method name are irrelevant: `obj.send(:update, attrs)` is silent,
  `obj.send(meth, attrs)` fires.
- One finding per line. A chained `obj.send(a).send(b)` is one call site to fix.

## When NOT to flag (and the pragma)

- `obj.send(:save)` / `user.try(:name)` → silent. The literal form is the fix, and `try(:name)`
  in particular is everyday Rails code that must never be noise.
- Commented out (`# obj.send(meth)`) or inside a `=begin`/`=end` block → silent.
- Quoted *inside a string* — an error message or guidance text that mentions the pattern
  (`raise ArgumentError, "use obj.send(:name), never obj.send(attr)"`) → silent. Code inside a
  `#{...}` interpolation is real code and still fires.
- Spec/test trees (`spec/`, `test/`, `fixtures/`, …) are out of scope: dispatching through a
  variable method name is ordinary, intentional code in shared examples and `described_class`
  metaprogramming.
- An audited dispatch — the name is allowlisted upstream, or the receiver is a `Socket` rather
  than a plain object — is suppressed explicitly:

```ruby
obj.send(method_name)  # security: allow-dynamic-dispatch
```

**`params.permit`-allowlisted loop variables are exempted (#848 corpus scan).** A real false
positive found against discourse/discourse: `allowed.each { |key| badge.public_send("#{key}=",
params[key]) if params[key] }`, where `allowed` had already been through
`params.permit(*allowed)` — Rails' own strong-parameters allowlist. The dispatched name is
caller-approved, not attacker-chosen, so this narrow shape (exact `<recv>.each { |key| ... }`,
the SAME name interpolated alone, a `.permit(` mentioning `<recv>` within a 10-line backward
lookback, and no reassignment of `<recv>` between the permit call and the dispatch) does not
fire. The reassignment check exists because an adversarial self-test on this exact fix found a
bypass: `params.permit(*allowed)` followed by `allowed = params[:x].split(",")` followed by the
same `.each` dispatch would otherwise still read as permit-derived, laundering a genuinely
attacker-rebuilt receiver through the exemption.

## Known bypasses (honest limits)

- **`Socket#send` / `UDPSocket#send` collide by name.** `sock.send(payload, 0)` is network I/O,
  not reflection, and this guard cannot tell the two apart from one line of text — it has no type
  information for the receiver. In Ruby network code that is a real false positive, and the
  pragma above is the intended correction. Brakeman does not hit this because it only analyzes
  Rails applications; agentsec scans whatever Ruby is in the repo.
- **Receiver-less `send(x)` is not detected.** Requiring the leading `.` is what keeps
  `send_report(user)` and a locally-defined `def send(...)` from firing; the cost is that a
  dispatch on implicit `self` is missed. Deliberate trade: the receiver-less form is rarer than
  the false positives the loose form would produce.
- **`try!` is not in scope.** Only the four methods named above are matched. `try!` is the same
  mechanic and would be a one-token widening, listed here rather than assumed away.
- **Single-line, no dataflow.** A call split across lines (`obj.send(\n  meth\n)`) is silent, and
  a method name that is a literal *at the call site* but was itself derived from user input
  upstream is not traced. The guard proves the call site's shape, not the value's provenance —
  same textual scope as `dynamic-import-non-literal`.
- **Percent-literals and heredocs are not string-aware.** Both `strip_ruby_comments` and this
  guard's own string-span pass track only `'...'`/`"..."`; a `%q()` body or a heredoc containing
  the pattern is not recognized as string text and could false-fire. Documented, not observed.

## What this guard does NOT prove

A clean scan means no single-line, explicit-receiver dispatch with a non-literal method name was
found in the scanned Ruby source. It says nothing about reflection reached another way —
`method(name).call`, `instance_variable_get`, `const_get`, `eval`, a `respond_to?`-gated dispatch
built across several lines, or a metaprogrammed `define_method` whose name comes from input.

## Canary plant

`dispatch.rb` — `record.send(params[:action])` inside a controller method, no pragma. Expected
rule: `ruby-dangerous-dispatch/non-literal-method-name`.

# Examples

```ruby
# FIRES -- the caller names the method
record.send(params[:action])
obj.__send__(meth)
obj.public_send(:"#{action}")
user.try(attr)
logger.debug("result: #{target.send(meth)}")   # interpolation is code

# SILENT -- the method is fixed at the call site
obj.send(:save)
obj.send(:update, attrs)
obj.send("save")
user.try(:name)
obj.send(method_name)  # security: allow-dynamic-dispatch
```

# Citations

[1] agentsec checklist item `3b-dynamic-method-dispatch` (§3b)
[2] OWASP:A03 (Injection)
[3] CWE-470 (Use of Externally-Controlled Input to Select Classes or Code — 'Unsafe Reflection')
[4] Brakeman, `lib/brakeman/checks/check_send.rb` (`Brakeman::CheckSend`) — pattern provenance;
    detection logic here is original
[5] Ruby core documentation, `Object#send` / `Object#public_send` — `send` invokes private and
    protected methods, `public_send` does not
