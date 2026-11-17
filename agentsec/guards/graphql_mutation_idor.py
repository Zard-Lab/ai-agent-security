"""Guard: GraphQL mutation resolver modifies an object with no ownership check (§2b, NS-2).

The GraphQL counterpart to `bola.py`'s REST-route BOLA check. `bola.py` is structurally
REST-route-shaped (`@app.get/post/put/patch/delete(...)` + a `{path_param}` id in the URL
template) — a GraphQL resolver function has neither of those, so it is invisible to `bola.py` by
construction, not by threshold. `2b-idor-prevention` was already `status: manual` (acknowledging
IDOR-in-general) but nothing GraphQL-specific or structural existed.

**Confirmed real-world motivation**: a synthetic gym-booking app's `cancelReservation` GraphQL
mutation took a reservation id argument and canceled that reservation without verifying it
belonged to the calling member — Claude Opus 4.6, red-teaming the app, found and exploited exactly
this gap to cancel another member's booking (Aikido Security research, TheHackerNews coverage,
2026-08).

Scoped to a MUTATION resolver specifically (not a query/read resolver, which `bola.py`'s own
broader REST coverage already treats as in-scope for GET routes): a mutation is a WRITE, so an
unscoped one lets an attacker actively modify/delete another user's resource, not merely read it —
the more severe half of the object-level-authorization gap.

**Detection**, mirroring `bola.py`'s own four-signal shape as closely as the different transport
allows:
  * a resolver decorator that is unambiguously a MUTATION, not a generic field — Strawberry's
    `@strawberry.mutation` (there is no ambiguity: `@strawberry.field` is used for both queries and
    mutations depending on which class it decorates, and telling those apart needs the enclosing
    class's own declaration, which `iter_functions`'s per-function block does not carry — so only
    the unambiguous decorator is matched), or Ariadne's `@<name>.field(...)` where the receiver
    name itself contains "mutation" (the conventional `mutation = MutationType()` binding);
  * an id-shaped parameter in the resolver's own signature (`reservation_id`, `booking_id`, a bare
    `id`) — the GraphQL-argument analogue of `bola.py`'s `{order_id}` URL path parameter;
  * a fetch-by-id in the body — reuses the exact same signal set `bola.py` uses
    (`.query.get`/`.filter`/`get_object_or_404`/`session.get`/`.find_one`/a Supabase
    `.select(...).eq(...)` chain), since a mutation resolver almost always fetches the target
    object before modifying it;
  * **no** authorization/ownership signal anywhere in the function — the exact same vocabulary
    `bola.py` uses (`current_user`, an auth-named `Depends(...)`, `user_id`, `owner`/`tenant`/
    `scope`/`require`/`permission` stems, `403`, `Forbidden`, ...). Duplicated rather than
    imported: `bola.py` is a heavily-reviewed, already-shipped guard (issues #307/#345/#364 all
    hardened this exact vocabulary), and this guard adding a new consumer of its private names
    is a larger, unrelated-feature touch on that file than duplicating the same regex text here.

Fires HIGH (one severity rank above `bola.py`'s MEDIUM — an unscoped WRITE is more severe than an
unscoped read, matching this project's own convention of grading a mutation/write-path finding
higher than the equivalent read-path one). Suppress an audited resolver with
`# security: allow-unscoped-mutation`.

**Known, accepted gap (disclosed, not silently assumed away)**: Graphene's mutation idiom is a
`class CancelReservation(graphene.Mutation): def mutate(self, info, reservation_id): ...` — the
"is this a mutation" signal lives on the ENCLOSING CLASS's base list, not on the `mutate` method's
own decorator stack, so `iter_functions`'s per-function block cannot see it. Resolving this would
need the same class-context-carrying machinery bola.py's own multi-file resolver work (`base.py`)
was built for elsewhere, and NS-2's own confirmed real-world instance (the gym-booking app) does
not use Graphene. Left as a documented false negative for v1 rather than half-building a
class-context resolver under this batch's own "standalone lift" framing.
"""
from __future__ import annotations

import re
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import (
    CanaryPlant,
    Guard,
    boundaried_stems,
    is_nonproduct_path,
    iter_files,
    iter_functions,
    pragma_present,
    python_scan_dirs,
    read,
    rel,
)

_STRAWBERRY_MUTATION = re.compile(r"@\s*strawberry\.mutation\b")
# The receiver is boundaried on the LEFT so the stem cannot bleed into an unrelated word:
# `@permutation_type.field(...)` / `@commutation_check.field(...)` are NOT Ariadne mutation
# types. A prefix is allowed only when it is its own `_`-separated segment (`root_mutation`),
# which keeps the real binding conventions firing. NOT `boundaried_stems`: that anchors both
# sides, which would reject `mutation_type` — the binding `MutationType()` actually produces.
_ARIADNE_MUTATION_FIELD = re.compile(r"@\s*(?:\w+_)?mutation\w*\.field\s*\(", re.IGNORECASE)

_DEF_HEADER = re.compile(r"\bdef\s+\w+\s*\(")
# An id-shaped resolver argument: a bare `id`, or a name ending `_id`/`Id`/`ID` (covers both
# Python's own snake_case convention and a camelCase GraphQL arg name left unconverted).
_ID_PARAM_NAME = re.compile(r"^(?:id|\w*(?:_id|Id|ID))$")

_FETCH_SIMPLE = re.compile(
    r"get_object_or_404\(|\.query\.get\(|\.filter(?:_by)?\(|session\.get\(|"
    r"\bdb\.get\(|\.find_one\(|\.get_or_404\("
)
# The identical object-level-authorization vocabulary bola.py uses (see module docstring for why
# this is duplicated rather than imported).
_AUTH = re.compile(
    r"current_user|request\.user|get_current_user|user_id|ownership|\bauth\b|is_admin|\b403\b|Forbidden|"
    + boundaried_stems("scope|require|owner|tenant", "permission"),
    re.IGNORECASE,
)
_PRAGMA = re.compile(r"#\s*security:\s*allow-unscoped-mutation")


def _signature_span(block: str, open_paren: int) -> str:
    """The text between a `def name(`'s opening `(` at `open_paren` and its matching close,
    exclusive of both. Bracket-aware so a type-annotation default value's own parens don't end
    the span early."""
    depth = 0
    i = open_paren
    n = len(block)
    while i < n:
        ch = block[i]
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return block[open_paren + 1 : i]
        i += 1
    return block[open_paren + 1 :]


def _has_id_param(block: str) -> bool:
    m = _DEF_HEADER.search(block)
    if not m:
        return False
    sig = _signature_span(block, m.end() - 1)
    for param in sig.split(","):
        name = param.strip().split(":")[0].split("=")[0].strip()
        if _ID_PARAM_NAME.match(name):
            return True
    return False


def _has_fetch(block: str) -> bool:
    if _FETCH_SIMPLE.search(block):
        return True
    return ".select(" in block and ".eq(" in block


def _is_mutation_resolver(block: str) -> bool:
    return bool(_STRAWBERRY_MUTATION.search(block) or _ARIADNE_MUTATION_FIELD.search(block))


class GraphqlMutationIdorGuard(Guard):
    id = "graphql-mutation-idor"
    title = "GraphQL mutation resolver modifies an object with no ownership check (possible IDOR)"
    area = "Login & access"

    # bookings.py: a @strawberry.mutation resolver taking a reservation_id, fetching the row by
    # id, with no ownership check anywhere in the body -> fires graphql-mutation-idor.
    canary_plant = CanaryPlant(
        files={
            "bookings.py": (
                "import strawberry\n\n\n"
                "@strawberry.type\n"
                "class Mutation:\n"
                "    @strawberry.mutation\n"
                "    def cancel_reservation(self, reservation_id: str) -> bool:\n"
                "        reservation = Reservation.query.get(reservation_id)\n"
                "        reservation.status = \"cancelled\"\n"
                "        return True\n"
            ),
        },
        expects=frozenset({"graphql-mutation-idor/unscoped-mutation"}),
    )

    def applies(self, profile: StackProfile) -> bool:
        return "python" in profile.features and "graphql" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []
        seen: set[Path] = set()
        for d in python_scan_dirs(root, profile):
            for f in iter_files(d, (".py",)):
                if f in seen:
                    continue
                seen.add(f)
                if is_nonproduct_path(rel(root, f), profile.archive_segments):
                    continue
                out.extend(self._scan(root, f))
        return out

    def _scan(self, root: Path, f: Path) -> list[Finding]:
        out: list[Finding] = []
        for lineno, block in iter_functions(read(f), filename=f):
            # A real comment in the resolver block only, never the phrase in a string there (#1040).
            if pragma_present(_PRAGMA, block, dialect="python"):
                continue
            if not _is_mutation_resolver(block):
                continue
            if not _has_id_param(block):
                continue
            if not _has_fetch(block):
                continue
            if _AUTH.search(block):
                continue
            out.append(
                Finding(
                    check_id=self.id,
                    severity="high",
                    title=self.title,
                    location=f"{rel(root, f)}:{lineno}",
                    message=(
                        "This GraphQL mutation resolver takes an id argument, fetches that "
                        "object, and modifies/deletes it — but shows no sign of checking the "
                        "object belongs to the authenticated caller. Any member can cancel, "
                        "delete, or modify another member's resource by passing their id "
                        "(OWASP API #1, BOLA/IDOR — the write-path, higher-severity half of "
                        "the same gap `bola` surfaces for reads)."
                    ),
                    remediation=(
                        "Scope the fetch to the caller before mutating "
                        "(`...filter(owner_id == current_user.id)` / supabase "
                        "`.eq(\"user_id\", current_user.id)`), and return a not-found error "
                        "(not a bare 403) when it doesn't match, so ids aren't enumerable. If "
                        "authorization is enforced elsewhere (a resolver middleware/directive), "
                        "suppress with `# security: allow-unscoped-mutation`."
                    ),
                    rule="graphql-mutation-idor/unscoped-mutation",
                    standards=["OWASP:A01"],
                )
            )
        return out
