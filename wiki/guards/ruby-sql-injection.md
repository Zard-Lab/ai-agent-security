---
type: Guard
title: "ruby-sql-injection"
description: "Rails/ActiveRecord raw SQL built from Ruby string interpolation instead of bind parameters."
timestamp: "2026-09-11T00:00:00Z"
guard_id: "ruby-sql-injection"
checklist_section: ["3b"]
standards: ["ASVS:1.2.4", "OWASP:A03"]
---

# Rails/ActiveRecord interpolated SQL

Flags an ActiveRecord query whose raw-SQL argument is a Ruby double-quoted string carrying a
`#{...}` interpolation. Extends checklist item `3b-sql-parameterized` — the Ruby counterpart to
`sqlalchemy-text-parameterized` (Python), `js-sql-injection` (JS/Node) and `go-sql-injection`
(Go), widening the same item rather than duplicating it. agentsec's second Ruby-language guard
. OWASP:A03 (Injection), ASVS:1.2.4, CWE-89.

## The threat

ActiveRecord's query methods accept SQL *fragments* as strings. Ruby evaluates a `#{...}`
interpolation before the string ever leaves the process, so the value is concatenated into the
SQL **text** — the adapter never sees a placeholder to bind it against:

```ruby
User.where("name = '#{params[:name]}'")                       # injectable
Order.find_by_sql("SELECT * FROM orders WHERE id = #{id}")    # injectable
Post.order("created_at #{params[:dir]}")                      # injectable (ORDER BY direction)
```

The attacker controls SQL syntax, not just a value: read or write arbitrary rows, defeat a
`WHERE`-clause authorization check, or (via `find_by_sql`/`exec_query`) run a statement of their
own choosing. `order`/`group`/`having` are the ones developers most often assume are safe because
"it's only a column name" — they are ordinary SQL text like the rest.

## Exploitability rationale

HIGH. Directly attacker-reachable in a Rails controller (`params[...]` interpolated into a scope
is the canonical shape), requires no chain, and yields data disclosure or authorization bypass on
the first request. Likelihood is high because the vulnerable form is *shorter* than the safe one:
`where("id = #{id}")` reads more naturally to someone coming from string formatting than
`where("id = ?", id)`.

## What counts as a hit (and what doesn't)

The guard anchors on the **ActiveRecord raw-SQL sinks** — `where`, `find_by_sql`, `order`,
`group`, `joins`, `pluck`, `exec_query`, `select`, `having`, `calculate` — and fires only when
that call's **SQL-text argument IS a double-quoted string literal containing `#{`**. The SQL-text
argument is the first positional one for every sink except `calculate(operation, column_name)`,
where it is the second (a sink listed but structurally unable to fire would be a dead check
reading as a live one, so the index is handled explicitly).

Both receiver forms are matched: `User.where(...)` and the bare `where(...)` Rails writes inside a
model body or a `scope :x, -> { ... }` lambda. A longer identifier that merely ends in a sink name
(`reselect`, `my_joins`) is rejected by a lookbehind.

## When NOT to flag (and the pragma)

All three of ActiveRecord's parameterized forms stay silent — they are the fix:

```ruby
User.where("name = ?", name)          # positional placeholder + bind argument
User.where("id = :id", id: id)        # named placeholder + bind hash
User.where(name: name)                # hash form — ActiveRecord always parameterizes it
Order.find_by_sql(["SELECT * FROM orders WHERE id = ?", id])   # array/bind form
```

Also silent: a single-quoted Ruby literal (`'...#{x}...'` does not interpolate at all), a `#`
comment or a `=begin`/`=end` block comment mentioning the pattern, a trailing comment on an
otherwise-clean line, and any interpolation outside a sink (`log.info("user #{id}")`,
`redirect_to "#{root_path}"`).

Spec/test trees (`spec/`, `test/`, `fixtures/`, …) are out of scope as a whole: fixture setup
and `let(:scope)` helpers splice literal flags into fragments as ordinary, intentional code. This
matches the three siblings on the same `3b-sql-parameterized` checklist item —
`sqlalchemy-text-parameterized`, `js-sql-injection` and `go-sql-injection` all skip the same
trees, so the identical shape gets the identical verdict whatever language it is written in.

Suppress an audited case — an interpolated column or table name drawn from a fixed internal
allowlist is the realistic one — on the call's own line:

```ruby
User.order("#{SORT_COLUMNS.fetch(key)} ASC")  # security: allow-ruby-sql-injection
```

### The hash-form decision, stated explicitly

`User.where(name: "#{prefix}_suffix")` — a hash **value** built by interpolation — does **not**
fire, and that is deliberate rather than a limitation. ActiveRecord parameterizes hash values
regardless of how the Ruby string was assembled: the value travels as a bind parameter and never
becomes SQL syntax. The injectable property is interpolation *inside the raw SQL text*, not
interpolation *inside a value*. The regex enforces this structurally — it is anchored to the
start of the extracted argument, so `name: "#{x}"` cannot match while `"name = #{x}"` does. The
same anchoring is what keeps an interpolated *bind* argument (`where("name = ?", "#{x}")`) out of
scope: arguments are split top-level first, and only the SQL-text one is examined.

The residual risk this accepts: if a hash value is used somewhere that is *not* parameterized
(an unusual custom scope that re-splices it into a fragment), this guard stays quiet. That
re-splicing site would itself be a sink call and would fire on its own.

## Known bypasses (honest limits)

- **Single physical line only.** A call split across lines — `User.where(\n  "id = #{id}"\n)` —
  is not matched. Same textual scope as every sibling SQL guard; no dataflow, no AST.
- **No variable lookback.** `sql = "SELECT ... #{id}"` on one line and `find_by_sql(sql)` on the
  next is not traced. `go-sql-injection` carries a 5-line lookback for its `fmt.Sprintf` shape;
  this guard does not yet. This assumption doesn't fully hold in practice — the #848 corpus scan
  against discourse/discourse found real cases where a variable interpolated at the sink was
  `.to_i`-coerced (provably safe) on an EARLIER line rather than inline, which this guard cannot
  see and so still fires on (a false positive in the conservative direction, not a missed real
  bug). A candidate widening, not a claim of coverage.
- **`.to_i`/`.to_f` coercion is only recognized INLINE at the interpolation site (#848 corpus scan
  fix).** `order("ARRAY[#{ids.map(&:to_i).join(",")}]")` correctly stays silent — every
  interpolated value is numeric-coerced, which can only render as digits/`.`/`-` and so cannot
  carry SQL syntax. But `rank_array_sql = "ARRAY[#{ids.map(&:to_i).join(",")}]"` on one line, then
  `order("... #{rank_array_sql} ...")` on another, still fires: the bare variable interpolated at
  the sink gives no visible evidence it was safely built, and this guard does not trace it back to
  its own (safe) assignment. Same "no variable lookback" limitation above, just for the specific
  numeric-coercion exception rather than for detection in general.
- **String concatenation is out of scope.** `where("name = '" + name + "'")` is equally
  injectable and does **not** fire — this guard targets the `#{...}` interpolation shape only.
  Concatenation is rare in idiomatic Ruby (interpolation is the language's preferred form), but
  it is a real gap, listed here rather than left implicit.
- **Heredocs and percent-literals are not seen.** `find_by_sql(<<~SQL)` with the interpolation in
  the heredoc body is missed, because `strip_ruby_comments` deliberately does not track Ruby's
  heredoc or `%q()`/`%Q()` forms (documented on that helper). Heredoc SQL is common enough in
  large Rails apps that this is the most material gap of the four.
- **No taint analysis.** An interpolation of a hardcoded internal constant fires exactly as
  loudly as one of `params[:x]` — the pragma is the intended correction, not a defect to fix
  later. Same posture as every sibling SQL guard.

## What this guard does NOT prove

A clean scan means no single-line interpolated ActiveRecord sink call was found in the scanned
Ruby source. It says nothing about SQL executed through a gem that wraps the connection, raw
`ActiveRecord::Base.connection.execute` with a variable-built string, a heredoc query, a stored
procedure, or SQL assembled in a view template (`.erb`, not scanned here).

## Canary plant

`user_search.rb` — `User.where("name = '#{name}'")` inside a method body, no pragma. Expected
rule: `ruby-sql-injection/interpolated-sql`.

## Provenance

The pattern was verified against Brakeman's real source (`lib/brakeman/checks/check_sql.rb`,
`Brakeman::CheckSQL`), cited here for provenance. The detection logic and every test fixture are
original — developed against the pattern description and ActiveRecord's documented query API, not
copied or derived from Brakeman's own Ruby implementation.

# Examples

```ruby
# FIRES — interpolated value becomes SQL text
User.where("name = '#{params[:name]}'")
Post.order("created_at #{params[:dir]}")
Post.joins("LEFT JOIN #{table} t ON t.id = posts.id")
User.calculate(:sum, "price * #{rate}")

# SILENT — the value stays a bind parameter
User.where("name = ?", name)
User.where("id = :id", id: id)
User.where(name: name)
User.where(name: "#{prefix}_suffix")     # hash value: still parameterized
Order.find_by_sql(["SELECT * FROM orders WHERE id = ?", id])

# SILENT — reviewed and suppressed
User.order("#{SORT_COLUMNS.fetch(key)} ASC")  # security: allow-ruby-sql-injection
```

# Citations

[1] agentsec checklist item `3b-sql-parameterized` (§3b)
[2] OWASP:A03 (Injection)
[3] ASVS:1.2.4
[4] CWE-89 (Improper Neutralization of Special Elements used in an SQL Command)
[5] Brakeman, `lib/brakeman/checks/check_sql.rb` (`Brakeman::CheckSQL`) — pattern provenance only
[6] Rails Security Guide, "SQL Injection" — ActiveRecord's parameterized query forms
