---
type: Guard
title: "ruby-mass-assignment"
description: "Rails mass-assignment: Strong Parameters disabled with permit!, or a model written straight from raw request params."
timestamp: "2026-09-11T00:00:00Z"
guard_id: "ruby-mass-assignment"
checklist_section: ["3a"]
standards: ["OWASP:A01"]
---

# Mass-assignment / over-posting (Ruby on Rails)

Flags Rails controllers that defeat or skip Strong Parameters. Extends checklist item
`3a-mass-assignment` — the Ruby counterpart to the existing `mass-assignment` (Python/FastAPI)
guard, covering the same requirement on a different mechanism rather than duplicating the item
(brakeman research batch). OWASP:A01 (Broken Access Control), CWE-915; OWASP API
Security lists the same class as API3:2023 (Broken Object Property Level Authorization).

## The threat

Rails binds a whole hash of attributes onto a model in one call. Since Rails 4 the framework
protects that with **Strong Parameters**: `ActionController::Parameters` refuses to be mass-assigned
until you have declared an allowlist with `.permit(:name, :email)`. The vulnerability is code that
opts back out of the protection.

```ruby
# DANGEROUS — permits every key the request carries:
User.create(params.permit!)

# DANGEROUS — no allowlist at all:
@user.update(params[:user])
```

The attacker's move is one extra JSON key. If `User` has an `admin`, `role`, `account_id`, or
`confirmed_at` column, `{"user": {"name": "x", "admin": true}}` writes it — a vertical privilege
escalation from a form that only ever displayed a name field. Nothing in the request log looks
unusual, and the vulnerability is invisible in the view layer, because the extra attribute never
appears in any template.

## Exploitability rationale

HIGH, matching the Python sibling and the checklist item's own severity. Trivial to attempt (append
a key to a request body an authenticated user already sends), trivial to discover (the model's
columns are usually inferable from the app's own JSON responses or a public schema), and it grants
exactly the attribute the attacker names. The historic proof is the 2012 GitHub incident, where a
researcher used Rails mass assignment to add his public key to the `rails` repository's deploy
keys — that incident is why Strong Parameters exists at all, and `permit!` is the switch that turns
it back off.

## What counts as a hit (and what doesn't)

Two rules, deliberately different in confidence.

**`ruby-mass-assignment/params-permit-bang`** — the high-confidence rule. A `.permit!` call whose
receiver chain is rooted at a `params`/`parameters`-named object:

```ruby
params.permit!                       # fires
params.require(:user).permit!        # fires
params[:user].permit!                # fires
@raw_params.permit!                  # fires
user_params.permit!                  # fires
```

The params-rooted receiver requirement is what keeps an application's own domain method out of it
(`@membership.permit!` in an app that models permissions → silent). `permit!` has no safe use on a
request parameters object: it is the documented escape hatch from the allowlist, so every match
fires unconditionally.

**`ruby-mass-assignment/unprotected-model-assignment`** — the narrower second rule. An ActiveRecord
persistence call on a **constant or instance-variable** receiver, whose first argument *textually
begins with* the token `params`, on a line containing no `.permit`:

```ruby
User.create(params[:user])                                      # fires
Admin::User.create!(params[:user])                              # fires
@user.update(params[:user])                                     # fires
@user.assign_attributes(params[:user])                          # fires
@user.update_attributes(params[:user])                          # fires (legacy Rails 4 API)
Comment.create(params[:c].merge(user_id: current_user.id))      # fires — merging is not permitting

User.create(params[:user].permit(:name, :email))                # silent — allowlisted inline
@user.update(params.require(:user).permit(:name))               # silent — allowlisted inline
User.create(user_params)                                        # silent — the conventional idiom
@user.update(name: params[:name], email: params[:email])        # silent — named args are an allowlist
User.where(params[:q])                                          # silent — a finder is not a write
```

Methods matched: `create`, `create!`, `update`, `update!`, `update_attributes`,
`update_attributes!`, `assign_attributes`. **`new` is deliberately not matched** — see below.

**Why a same-line `.permit` check is sufficient here, and not a shortcut.** The rule only matches
when the argument starts with the *literal token* `params`, so any permitting of that object has to
happen inside the same expression. A same-line test therefore sees every protection that could
apply to a matched call; a multi-line lookback would find nothing extra and would only add FPs. The
cost is paid on the other side, as a documented miss (below), not as noise.

## When NOT to flag (and the pragma)

- The conventional Rails controller — a private `user_params` helper returning
  `params.require(:user).permit(...)`, used by every action — is silent end to end. That is the
  shape the remediation text steers toward.
- A commented-out example, in a `#` line comment or a `=begin`/`=end` block, is silent.
- An audited exception (a genuinely schemaless, non-sensitive settings blob) is suppressed inline:

```ruby
params.permit!  # security: allow-ruby-mass-assignment
```

The pragma is checked against the **comment-only view** of the source line (#424) — stripping blanks
the pragma's own text, so a post-strip check would silently never match. (Same ordering trap
`ruby-weak-crypto` documents; caught here again by the adversarial self-test before any formal test
existed.)

## Known bypasses (honest limits)

- **`.new` is out of scope, by choice.** `User.new(params[:user])` is the textbook example, but
  `.new` on a capitalized constant is also how every Rails service object, query object, and form
  object is constructed (`OrderCreator.new(params[:order]).call`) — and nothing textual separates
  a model from a PORO. Including it would trade a real, common false-positive class for coverage of
  a shape `create`/`update` already represent. A `Model.new(params[:x])` followed by a bare `.save`
  is the concrete miss this buys; `create`/`create!` (the same thing in one call) is caught.
- **No dataflow.** A params object laundered through a local is not traced:
  `attrs = params[:user]` then `User.create(attrs)` → silent. This is the deliberate boundary of a
  textual guard; Brakeman catches it because it parses the app and resolves assignments, which a
  zero-dependency guard cannot.
- **Single-line only.** A call split across lines (`User.create(\n  params[:user]\n)`) does not
  match, because the receiver, method, and argument never appear on one line.
- **Lowercase local receivers are not matched** for shape 2 (`user.update(params[:user])` →
  silent). That exclusion is load-bearing: Ruby's `Hash#update` is an alias for `merge!`, and
  lowercase locals are where non-model `update` calls actually live (`options.update(...)`).
- **The remaining `update` false positive is the instance-variable Hash.**
  `@filters.update(params[:filters])` — an ivar holding a plain Hash, not a model — fires. It is
  rare in real controllers (Rails code reaches for `merge` there) and the finding still points at
  raw request data flowing into a bulk write, but it is a genuine FP, not a hypothetical one. The
  pragma is the correction.
- **String literals are not blanked.** `strip_ruby_comments` is string-aware for the purpose of not
  mistaking a `#` inside a literal for a comment, but it does not blank the literal's *contents* —
  so `log("never call params.permit!")` fires. Identical behavior to `ruby-weak-crypto`; there is
  no `strip_ruby_strings` helper in `guards/base.py` today.
- **Model-side allowlists are not read.** An app that additionally protects itself with
  `attr_readonly`, a `before_save` filter, or by simply not having a privileged column still gets
  the finding — the guard reasons about the controller, not the schema.

## What this guard does NOT prove

A clean scan means no `permit!` and no raw-`params` persistence call was found on a single line of
the scanned Ruby source. It says nothing about mass assignment reached through a local variable, a
helper method that itself calls `permit!` elsewhere, a `.new`-plus-`.save` pair, a GraphQL or gRPC
entry point that never touches `ActionController::Parameters`, or `permit_all_parameters = true`
set globally in an initializer.

## Canary plant

`users_controller.rb` — `User.create(params.permit!)` inside a controller action, no pragma.
Expected rule: `ruby-mass-assignment/params-permit-bang`. (The line also matches shape 2's call
shape; the guard reports the higher-confidence bang rule only, which the test suite pins.)

# Examples

```ruby
# VULNERABLE — Strong Parameters turned off wholesale.
class UsersController < ApplicationController
  def create
    @user = User.create(params.permit!)
  end
end

# VULNERABLE — never allowlisted in the first place.
class UsersController < ApplicationController
  def update
    @user = User.find(params[:id])
    @user.update(params[:user])
  end
end

# SAFE — the conventional idiom: one allowlist, every action.
class UsersController < ApplicationController
  def create
    @user = User.create(user_params)
  end

  def update
    @user = User.find(params[:id])
    @user.update(user_params)
  end

  private

  def user_params
    params.require(:user).permit(:name, :email)
  end
end
```

# Citations

[1] agentsec checklist item `3a-mass-assignment` (§3a)
[2] OWASP:A01 (Broken Access Control); OWASP API Security API3:2023 (Broken Object Property Level
    Authorization)
[3] CWE-915 (Improperly Controlled Modification of Dynamically-Determined Object Attributes)
[4] Brakeman, `lib/brakeman/checks/check_mass_assignment.rb` (`Brakeman::CheckMassAssignment`) —
    pattern provenance only; detection logic here is original
[5] Rails Guides, Action Controller Overview — Strong Parameters
[6] GitHub mass-assignment incident (March 2012) — the origin of Strong Parameters
