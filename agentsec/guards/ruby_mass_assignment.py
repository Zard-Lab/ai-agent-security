"""Guard: Rails mass-assignment / over-posting via defeated Strong Parameters (checklist §3a).

The Ruby counterpart to agentsec's existing `mass-assignment` guard (Python/FastAPI:
`setattr`-from-`.dict()` loops, `update().values(**body.dict())`). Same requirement — a request
body must never be bound wholesale onto a database model — but a completely different mechanism:
Rails ships an *opt-in allowlist* API, `ActionController::Parameters`, and the vulnerability is
code that opts back out of it. So this extends the same `3a-mass-assignment` checklist item
rather than duplicating it.

Pattern verified against Brakeman's real source (`lib/brakeman/checks/check_mass_assignment.rb`,
`Brakeman::CheckMassAssignment`) — the class name and file are cited for provenance; the detection
logic, the regexes, and the test fixtures here are original, developed independently against the
pattern description, not copied or derived from Brakeman's own (Ruby) implementation.

Fires HIGH on two shapes:

  * **`params.permit!`** (`ruby-mass-assignment/params-permit-bang`) — the bang form permits
    **every** key the request carries, with no allowlist at all. It is Strong Parameters'
    explicit escape hatch, and using it puts the controller back in the pre-Rails-4
    `attr_accessible` world: any attribute the model exposes (`admin`, `role`, `account_id`,
    `confirmed_at`) can be set by adding one JSON key. This is the highest-confidence shape —
    a literal, unambiguous method call with no argument analysis needed. The receiver chain must
    be rooted at a `params`/`parameters`-named object (`params`, `params.require(:user)`,
    `params[:user]`, `@raw_params`), so a domain object with its own `permit!` method is not
    mistaken for Strong Parameters.

  * **Unprotected model write fed raw `params`**
    (`ruby-mass-assignment/unprotected-model-assignment`) — an ActiveRecord persistence call
    (`create`, `create!`, `update`, `update!`, `update_attributes`, `update_attributes!`,
    `assign_attributes`) on a **constant or instance-variable receiver** whose first argument
    *textually begins with* `params`, and where the line contains no `.permit` anywhere:
    `User.create(params[:user])`, `@user.update(params[:user])`. The safe inline form
    `User.create(params[:user].permit(:name, :email))` carries `.permit` on that same line and
    stays silent, and the canonical Rails idiom `User.create(user_params)` never matches at all
    because its argument is a helper method, not `params`.

**Why a same-line check is sufficient, not a shortcut.** Shape 2 only matches when the argument
*starts with the literal token* `params`. Any permitting of that object therefore has to happen in
the same expression — `params[:user].permit(...)` or `params.require(:user).permit(...)` — so a
same-line `.permit` test sees every protection that could apply to a matched call. A multi-line
lookback would add nothing here; what it would add is FPs, because the matched shapes are exactly
the ones with no earlier binding step. The flip side is an honest, documented gap: a params object
laundered through a local (`attrs = params[:user]` then `User.create(attrs)`) is NOT matched — that
would need dataflow this guard deliberately does not attempt.

**`.new` is deliberately out of scope.** `User.new(params[:user])` is the textbook example, but
`.new` on a capitalized constant is also how every Rails service object, query object, and form
object is built (`OrderCreator.new(params[:order]).call`), and nothing textual separates the two.
Including it would trade a real FP class for coverage of a shape `create`/`update` already
represent. Precision over coverage — see the design doc's "Known bypasses".

**Suppress** an audited case with an inline pragma:

    params.permit!  # security: allow-ruby-mass-assignment

**Checklist item:** `3a-mass-assignment`.
"""
from __future__ import annotations

import re
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import CanaryPlant, Guard, comment_view, iter_files, read, rel, ruby_scan_dirs, strip_ruby_comments

_PRAGMA = re.compile(r"#\s*security:\s*allow-ruby-mass-assignment")

_STANDARDS = ["OWASP:A01"]

# A receiver rooted at a params-named object: `params`, `@params`, `user_params`,
# `@raw_parameters`. The lookbehind keeps this from matching mid-identifier or mid-chain
# (`foo.user_params` / `my_params_helper`), so a domain object that happens to define its own
# `permit!` is not mistaken for ActionController::Parameters.
_PARAMS_ROOT = r"(?<![A-Za-z0-9_.])@{0,2}\w*(?:params|parameters)\b"
# One link of a Ruby method/index chain: `.require(:user)`, `.to_h`, `[:user]`.
_CHAIN_LINK = r"(?:\s*\.\s*\w+[!?]?(?:\s*\([^()]*\))?|\s*\[[^\[\]]*\])"

# Shape 1: `params.permit!`, `params.require(:user).permit!`, `params[:user].permit!`.
_PERMIT_BANG = re.compile(_PARAMS_ROOT + _CHAIN_LINK + r"*?" + r"\s*\.\s*permit!")

# Shape 2: an ActiveRecord persistence call on a constant (`User`, `Admin::User`) or an
# instance variable (`@user`), whose first argument begins with the literal token `params`.
# `.new` is intentionally absent (see the module docstring).
_MODEL_ASSIGN = re.compile(
    r"(?<![A-Za-z0-9_.])"
    r"(?:@{1,2}\w+|[A-Z]\w*(?:::[A-Z]\w*)*)"
    r"\s*\.\s*(?:create!?|update_attributes!?|update!?|assign_attributes)"
    r"\s*\(\s*params\b",
)
# Any `.permit`/`.permit!` on the line means the params object was run through an allowlist
# (or through shape 1, which reports it separately) — shape 2 stands down either way.
_PERMIT_GUARD = re.compile(r"\.\s*permit\b")


class RubyMassAssignmentGuard(Guard):
    id = "ruby-mass-assignment"
    title = "Rails mass-assignment: Strong Parameters defeated or bypassed"
    area = "Code safety"

    # users_controller.rb: params.permit! -> ruby-mass-assignment/params-permit-bang.
    canary_plant = CanaryPlant(
        files={
            "users_controller.rb": (
                "class UsersController < ApplicationController\n"
                "  def create\n"
                "    User.create(params.permit!)\n"
                "  end\n"
                "end\n"
            ),
        },
        expects=frozenset({"ruby-mass-assignment/params-permit-bang"}),
    )

    def applies(self, profile: StackProfile) -> bool:
        return "ruby" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []
        seen: set[Path] = set()
        for d in ruby_scan_dirs(root, profile):
            for f in iter_files(d, (".rb",)):
                if f in seen:
                    continue
                seen.add(f)
                out.extend(self._scan(root, f))
        return out

    def _scan(self, root: Path, f: Path) -> list[Finding]:
        out: list[Finding] = []
        text = read(f)
        # The pragma check runs on the COMMENT-ONLY view (#424) — it IS the comment `strip_ruby_comments` below
        # would blank, so checking it after stripping would always miss it (the exact ordering bug
        # `ruby_weak_crypto.py` documents; caught again here by the adversarial self-test).
        view_lines = comment_view(text, "ruby").splitlines()  # same length: comments only (#424)
        # Blank comments so a documented example in a `#` note or a `=begin`/`=end` block never
        # fires. `strip_ruby_comments` preserves length and splitlines() count exactly (tested),
        # so the two lists always pair up — `strict=True` documents that invariant.
        code_lines = strip_ruby_comments(text).splitlines()
        for i, (view, line) in enumerate(zip(view_lines, code_lines, strict=True), start=1):
            if _PRAGMA.search(view):
                continue
            if _PERMIT_BANG.search(line):
                out.append(self._permit_bang_finding(root, f, i))
            elif _MODEL_ASSIGN.search(line) and not _PERMIT_GUARD.search(line):
                out.append(self._model_assign_finding(root, f, i))
        return out

    def _permit_bang_finding(self, root: Path, f: Path, line: int) -> Finding:
        return Finding(
            check_id=self.id,
            severity="high",
            title="Strong Parameters disabled with `permit!` — every request key is assignable",
            location=f"{rel(root, f)}:{line}",
            message=(
                "`permit!` marks the whole parameters hash as permitted, with no allowlist. Any "
                "attribute the model exposes — `admin`, `role`, `account_id`, `confirmed_at` — can "
                "then be set by adding one key to the request body, which is privilege escalation "
                "by over-posting."
            ),
            remediation=(
                "Replace `permit!` with an explicit allowlist of the attributes this action is "
                "meant to accept: `params.require(:user).permit(:name, :email)`. If the payload is "
                "genuinely schemaless and non-sensitive (a settings blob stored as JSON, not model "
                "attributes), suppress with `# security: allow-ruby-mass-assignment` after "
                "confirming no privileged attribute is reachable."
            ),
            rule="ruby-mass-assignment/params-permit-bang",
            standards=list(_STANDARDS),
        )

    def _model_assign_finding(self, root: Path, f: Path, line: int) -> Finding:
        return Finding(
            check_id=self.id,
            severity="high",
            title="Model written from raw request params without a Strong Parameters allowlist",
            location=f"{rel(root, f)}:{line}",
            message=(
                "An ActiveRecord persistence call is fed the request params object directly, with "
                "no `.permit(...)` allowlist on it. Every key the caller sends is written to the "
                "record, including attributes the form never showed."
            ),
            remediation=(
                "Filter the params through Strong Parameters first — either inline "
                "(`User.create(params.require(:user).permit(:name, :email))`) or, preferably, via "
                "the conventional private helper (`def user_params; "
                "params.require(:user).permit(:name, :email); end`) so one allowlist serves every "
                "action in the controller."
            ),
            rule="ruby-mass-assignment/unprotected-model-assignment",
            standards=list(_STANDARDS),
        )
