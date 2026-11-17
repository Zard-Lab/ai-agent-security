"""Guard: dangerous dynamic method dispatch in Ruby (checklist §3b, new item).

`Object#send` / `#__send__` / `#public_send` and Rails' `#try` all invoke a method chosen at
runtime by their FIRST argument. When that argument is a static literal
(`obj.send(:save)`) the call site is fixed and safe. When it is a bare variable, a method
call, a hash/params lookup, or an interpolated value, whoever controls that value chooses
WHICH method runs on the receiver:

    obj.send(params[:action])   # attacker picks any method on obj -- arbitrary dispatch
    obj.send(:save)             # static literal symbol -> safe, never fires

`send` and `__send__` additionally **bypass method visibility on purpose**, so the reachable
set includes the receiver's private and protected methods, not just its public API. CWE-470
(Use of Externally-Controlled Input to Select Classes or Code -- 'Unsafe Reflection'),
OWASP:A03 (Injection).

Pattern verified against Brakeman's real source (`lib/brakeman/checks/check_send.rb`,
`Brakeman::CheckSend`) -- the class name and file are cited for provenance; the detection
logic and every test fixture here are original, developed independently against the pattern
description, not copied or derived from Brakeman's own (Ruby) implementation.

Fires HIGH on an explicit-receiver call to `send`/`__send__`/`public_send`/`try` whose first
argument is anything other than a plain symbol literal (`:name`, `:save!`, `:valid?`) or a
plain quoted string literal (`"name"`/`'name'`). A symbol BUILT by interpolation
(`obj.public_send(:"#{action}")`) is not a plain literal and fires.

A dispatched name that is a bare block-parameter identifier of an `.each` loop, where the
iterated receiver was already passed through Rails' own strong-parameters `.permit(...)` call
earlier in the same method, is a caller-APPROVED name — not attacker-chosen — and does NOT fire
even though the argument is not a plain literal (#848 corpus scan):

    allowed.each { |key| obj.public_send("#{key}=", params[key]) }  # after params.permit(*allowed)
                                                                     # -> does NOT fire

This exemption is intentionally narrow: it requires the exact `<recv>.each { |key| ... }` shape
with the SAME name interpolated alone (`"#{key}"`/`"#{key}="`, nothing concatenated), a `.permit(`
call mentioning `<recv>` within a short backward lookback, and no reassignment of `<recv>` between
that `.permit(` call and the dispatch — a receiver rebuilt from something else after being
permitted still fires, since the allowlist protection no longer holds.

Suppress an audited dispatch (the method name is already allowlisted upstream, or the
receiver is a `Socket` rather than a plain object) with:

    obj.send(method_name)  # security: allow-dynamic-dispatch
"""
from __future__ import annotations

import re
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import (
    CanaryPlant,
    Guard,
    comment_view,
    is_nonproduct_path,
    iter_files,
    read,
    rel,
    ruby_scan_dirs,
    strip_ruby_comments,
)

# An EXPLICIT-receiver dispatch call: `obj.send(`, `obj&.send(`, `obj.public_send(`, ...
# The leading `\.` is what keeps an unrelated method whose name merely ENDS in one of these
# (`foo.resend(x)`, `retry_send(x)`) from matching, and it also excludes the receiver-less
# `send(x)` form (implicit self) -- see the guard doc's known-limits section.
_DISPATCH = re.compile(r"\.\s*(?:send|__send__|public_send|try)\s*\(")

# The two SAFE first-argument shapes. Both are anchored with `fullmatch` semantics (`^...$`
# against the stripped argument) because a literal is only safe when it is the WHOLE argument:
# `:"#{action}"`, `"run_#{x}"` and `cmd || :noop` all contain literal-looking text but are not
# plain literals, and every one of them must still fire.
_SAFE_SYMBOL = re.compile(r"^:[A-Za-z_][A-Za-z0-9_]*[?!=]?$")
_SAFE_STRING = re.compile(r"^(?:\"[A-Za-z_][A-Za-z0-9_]*[?!=]?\"|'[A-Za-z_][A-Za-z0-9_]*[?!=]?')$")

_PRAGMA = re.compile(r"#\s*security:\s*allow-dynamic-dispatch")

_STANDARDS = ["OWASP:A03", "CWE-470"]

# The dispatched-name argument is EXACTLY one bare identifier interpolated alone -- `"#{key}"` or
# a setter form `"#{key}="` -- nothing else concatenated in. A broader shape (`"#{key}_x"`,
# `"prefix_#{key}"`) is not the narrow allowlisted-loop-variable idiom below and is not exempted.
_BARE_INTERPOLATED_IDENT = re.compile(r'^(?:"#\{(\w+)\}=?"|\'#\{(\w+)\}=?\')$')

# `<recv>.each { |<param>| ... }` / `.each do |<param>| ... end` -- the receiver and the block's
# own parameter name, so a same-named identifier dispatched inside the block can be checked
# against a receiver that is itself a Rails strong-parameters allowlist (#848 corpus scan).
_EACH_BLOCK = re.compile(r"\b(\w+)\s*\.\s*each\s*(?:\{|do\b)\s*\|\s*(\w+)\s*\|")

_PERMIT_CALL = re.compile(r"\.permit\s*\(")

_LOOKBACK_LINES = 10

# A `params`/`request` TOKEN — used below to test whether a receiver's own visible assignment
# looks built from user input rather than developer-authored. `\b`-bounded so `params_list` (a
# different identifier that merely starts with the word) doesn't false-match.
_PARAMS_OR_REQUEST_TOKEN = re.compile(r"\bparams\b|\brequest\b")


def _assign_regex(receiver: str) -> re.Pattern[str]:
    """A line-start assignment to `receiver`: bare `=` (not `==`) or a compound operator
    (`||=`/`&&=`/`+=`/`-=`/`*=`/`/=`).

    PR #884 review, found independently while implementing Dean's design-call fix below (not one
    of his 4 named findings): the ORIGINAL version of this regex required the compound-operator
    group to be followed by ANOTHER literal `=` (`(?:\\+=|-=|...)?=`) — real Ruby syntax never has
    that second `=`, so a compound reassignment (`allowed -= [...]`) silently never matched at all,
    meaning `_reassigned_between`'s own adversarial-bypass protection (added for #848) was
    non-functional for every compound-assignment form, verified directly: `'allowed -= [:x]'`
    against the old pattern returns no match. Each compound operator is now a COMPLETE alternative
    in its own right, not a prefix requiring a second `=`."""
    return re.compile(rf"^\s*{re.escape(receiver)}\s*(?:\|\|=|&&=|\+=|-=|\*=|/=|=(?!=))")


def _reassigned_between(code_lines: list[str], after_idx: int, before_idx: int, receiver: str) -> bool:
    """True if `receiver` is reassigned (`=`, `+=`, `-=`, `||=`, ...) on any line strictly between
    `after_idx` and `before_idx` (both 0-based, exclusive) — i.e. the enumerable was rebuilt from
    something else AFTER it went through `.permit`, which would launder an attacker-controlled
    replacement through the exemption below if not caught (own adversarial self-test, #848)."""
    assign = _assign_regex(receiver)
    return any(assign.match(code_lines[k]) for k in range(after_idx + 1, before_idx))


def _receiver_assignment_is_safe(code_lines: list[str], permit_idx: int, receiver: str) -> bool:
    """True only if `receiver`'s NEAREST visible assignment strictly BEFORE `permit_idx` (0-based),
    within the same backward lookback window, exists AND its right-hand side contains no
    `params`/`request` token — i.e. `receiver` looks like a developer-authored allowlist, not
    something built directly from the request.

    PR #884 review design call (Dean's suggested safe direction): `params.permit(*allowed)`
    validates NOTHING about `allowed` itself — Strong Parameters permits whatever field names it is
    handed. The exemption below assumes `receiver` is a developer-authored list (the idiomatic
    Rails pattern: define your own permitted-fields list, THEN pass it to `.permit`); it never
    checked that assumption. `allowed = params[:fields]` immediately before `params.permit(*allowed)`
    silently passed the old check, since `.permit(` mentioning `allowed` was treated as sufficient
    proof by itself. SAFE DIRECTION: no visible assignment to `receiver` anywhere in the lookback
    window is NOT assumed safe — returns False (distinguishing "hardcoded" from a scanner blind spot
    is genuinely hard with a regex; the same design principle #848's other guard fixes hold — under-
    exempt rather than over-exempt)."""
    assign = _assign_regex(receiver)
    lo = max(0, permit_idx - _LOOKBACK_LINES)
    for j in range(permit_idx - 1, lo - 1, -1):
        if assign.match(code_lines[j]):
            return not _PARAMS_OR_REQUEST_TOKEN.search(code_lines[j])
    return False


def _receiver_permit_derived(code_lines: list[str], lineno_idx: int, receiver: str) -> bool:
    """True if the NEAREST `.permit(...)` call mentioning `receiver` (as `params.permit(*allowed)`'s
    splat argument, or as `allowed.permit(...)`'s own receiver) within a short backward lookback of
    `lineno_idx` (0-based) is not followed by a reassignment of `receiver` before `lineno_idx`, AND
    `receiver`'s own visible assignment (if any) doesn't look built from `params`/`request`.
    `.permit` is Rails' own strong-parameters allowlist call — an enumerable built from it holds
    caller-APPROVED names, not attacker-chosen ones, however those names later get dispatched
    (#848 corpus scan: discourse/discourse's `allowed.each { |key| badge.public_send("#{key}=",
    params[key]) if params[key] }`, where `allowed` had already been through
    `params.permit(*allowed)`). The reassignment check guards against the adversarial case where
    `receiver` is rebuilt from something unsafe AFTER the permit call and BEFORE the dispatch; the
    assignment-provenance check (PR #884 review) guards the case where `receiver` was never safe
    to begin with, permit call or not."""
    ident = re.compile(rf"\b{re.escape(receiver)}\b")
    lo = max(0, lineno_idx - _LOOKBACK_LINES)
    for j in range(lineno_idx, lo - 1, -1):
        ln = code_lines[j]
        if _PERMIT_CALL.search(ln) and ident.search(ln):
            if _reassigned_between(code_lines, j, lineno_idx, receiver):
                return False
            return _receiver_assignment_is_safe(code_lines, j, receiver)
    return False


def _string_text_spans(line: str) -> list[tuple[int, int]]:
    """Index ranges of one line that are string-literal TEXT, so a `.send(` merely MENTIONED
    inside a message/template string is not read as a call site.

    `strip_ruby_comments` deliberately preserves string content (this guard needs it -- it has
    to read the argument's literal text), so the FP it would otherwise leave has to be closed
    here. A `#{...}` interpolation inside a double-quoted string is real CODE, so it is
    excluded from the returned spans: `"... #{obj.send(meth)}"` still fires.

    Single-line and quote-based, like every other stripper in this family: a heredoc body or a
    `%w[]`/`%q()` percent literal is not tracked (see the guard doc's known-limits section)."""
    spans: list[tuple[int, int]] = []
    i, n = 0, len(line)
    quote = ""
    start = 0
    while i < n:
        c = line[i]
        if not quote:
            if c in "\"'":
                quote, start = c, i
            i += 1
            continue
        if c == "\\":  # an escaped char never closes the literal
            i += 2
            continue
        if quote == '"' and c == "#" and i + 1 < n and line[i + 1] == "{":
            spans.append((start, i))  # string text ends; interpolated CODE begins
            depth = 1
            i += 2
            while i < n and depth:
                if line[i] == "{":
                    depth += 1
                elif line[i] == "}":
                    depth -= 1
                i += 1
            start = i  # string text resumes after the matching `}`
            continue
        if c == quote:
            spans.append((start, i + 1))
            quote = ""
        i += 1
    if quote:  # unterminated on this line (a continuation) -- treat the tail as string text
        spans.append((start, n))
    return spans


def _first_arg(line: str, paren: int) -> str:
    """Everything from just after `paren` to the matching close (best-effort: up to the first
    top-level comma or the line's trailing close-paren). Mirrors
    `dynamic_import_non_literal._first_arg`, the Python-side sibling of this check."""
    rest = line[paren + 1 :]
    depth = 0
    for i, ch in enumerate(rest):
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            if depth == 0:
                return rest[:i]
            depth -= 1
        elif ch == "," and depth == 0:
            return rest[:i]
    return rest.rstrip().rstrip(")")


def _is_dynamic(arg: str) -> bool:
    """True when `arg` is NOT a plain symbol/string literal, i.e. the dispatched method name is
    picked at runtime. An empty argument (a call continued on the next line, or a bare `.try()`)
    is NOT treated as dynamic -- this guard is single-line and does not guess across lines."""
    a = arg.strip()
    if not a:
        return False
    return not (_SAFE_SYMBOL.match(a) or _SAFE_STRING.match(a))


class RubyDangerousDispatchGuard(Guard):
    id = "ruby-dangerous-dispatch"
    title = "Dynamic method dispatch with a non-literal, attacker-influenceable method name"
    area = "Code safety"

    # obj.send() with an attacker-controlled params lookup ->
    # ruby-dangerous-dispatch/non-literal-method-name (HIGH).
    canary_plant = CanaryPlant(
        files={
            "dispatch.rb": (
                "class ReportsController\n"
                "  def run(record, params)\n"
                "    record.send(params[:action])\n"
                "  end\n"
                "end\n"
            ),
        },
        expects=frozenset({"ruby-dangerous-dispatch/non-literal-method-name"}),
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
                # Spec/test trees are the one place where dispatching through a variable method
                # name is ordinary, intentional code (shared examples, `described_class.send`
                # metaprogramming), so they are out of scope rather than pragma'd file by file.
                if is_nonproduct_path(rel(root, f), profile.archive_segments):
                    continue
                out.extend(self._scan(root, f))
        return out

    def _scan(self, root: Path, f: Path) -> list[Finding]:
        out: list[Finding] = []
        text = read(f)
        # The pragma check runs on the COMMENT-ONLY view (#424) -- it IS the comment `strip_ruby_comments` below
        # would blank, so checking it after stripping would always miss it (the same ordering bug
        # the sibling `ruby_weak_crypto` guard caught in its own adversarial self-test).
        view_lines = comment_view(text, "ruby").splitlines()  # same length: comments only (#424)
        # Blank comments so a documented example in a `#` note never fires. String CONTENT is
        # preserved by `strip_ruby_comments`, which this guard depends on: it has to read the
        # argument's literal text to decide whether it is a plain literal. The helper preserves
        # length and splitlines() count exactly (tested), so the two lists always pair up --
        # `strict=True` documents that invariant, not just quiets the linter.
        code_lines = strip_ruby_comments(text).splitlines()
        for i, (view, line) in enumerate(zip(view_lines, code_lines, strict=True), start=1):
            if _PRAGMA.search(view):
                continue
            spans = _string_text_spans(line) if ('"' in line or "'" in line) else []
            for m in _DISPATCH.finditer(line):
                if any(s <= m.start() < e for s, e in spans):
                    continue  # a `.send(` written inside a message/template string, not a call
                arg = _first_arg(line, m.end() - 1)
                if not _is_dynamic(arg):
                    continue
                ident_m = _BARE_INTERPOLATED_IDENT.match(arg.strip())
                if ident_m:
                    ident_name = ident_m.group(1) or ident_m.group(2)
                    block_m = _EACH_BLOCK.search(line[: m.start()])
                    if (
                        block_m
                        and block_m.group(2) == ident_name
                        and _receiver_permit_derived(code_lines, i - 1, block_m.group(1))
                    ):
                        continue  # dispatched name drawn from a params.permit-derived allowlist
                out.append(self._finding(root, f, i))
                break  # one finding per line; a chained dispatch is one call site to fix
        return out

    def _finding(self, root: Path, f: Path, line: int) -> Finding:
        return Finding(
            check_id=self.id,
            severity="high",
            title=self.title,
            location=f"{rel(root, f)}:{line}",
            message=(
                "A method is dispatched dynamically (send/__send__/public_send/try) with a "
                "method name that is not a static literal (a bare variable, a params/hash "
                "lookup, or an interpolated value). If that name is caller-influenceable, the "
                "caller chooses which method runs on the receiver -- and send/__send__ "
                "deliberately bypass visibility, so private methods are reachable too."
            ),
            remediation=(
                "Validate the method name against a fixed allowlist before dispatching, or "
                "replace the dispatch with an explicit case/hash mapping of permitted actions. "
                "Where a dynamic call is unavoidable, prefer `public_send` over `send` so "
                "private methods stay unreachable."
            ),
            rule="ruby-dangerous-dispatch/non-literal-method-name",
            standards=list(_STANDARDS),
        )
