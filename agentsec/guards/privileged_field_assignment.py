"""Guard: privileged field written from the request body with no caller-privilege check (§2b).

A state-changing route (`@router.post/put/patch(...)`) that copies a privileged field
straight from the request body onto a stored object — `user.role = body.role`,
`setattr(user, "is_admin", payload.is_admin)` — lets any authenticated caller escalate
their own or another account's privilege by simply adding that field to the JSON they
send, unless the handler *also* checks the caller's own privilege before writing it.
This is Broken Function-Level Authorization (OWASP API5) reached through a named field
rather than a full-dict splat (`mass-assignment`'s bind-the-whole-body pattern) — a
narrower, single-field variant CVE-2024-0795 (AnythingLLM admin-creation bypass) showed
in the wild: the create-user handler wrote a caller-supplied `role` field onto the new
account with no check that the *caller* already held admin.

Conservative — fires only when a state-changing route handler has ALL of:
  * a route decorator (`@router.post/put/patch(...)` or `@app.post/put/patch(...)`);
  * an explicit privileged-field assignment from a request-body variable — either
    `<obj>.<field> = <body>.<field>` or `setattr(<obj>, "<field>", <body>.<field>)`,
    where `<field>` is a name from the privileged set (role, is_admin, is_staff,
    is_superuser, permission(s), scope(s), admin);
  * **no** privilege/authorization signal anywhere in the function (`current_user`,
    an auth-named `Depends(get_current_user)`, `Security(...)`, `require_admin`, `require_role`,
    `403`, `Forbidden`; a bare non-auth `Depends(get_db)` does NOT count — issue #307), and
    no guard-shaped bare privilege factory in the route's own `dependencies=[...]` list
    (`dependencies=[requires_system_write_role()]`). Neither an authentication-only
    `requires_authenticated()` (#872) nor a call that only names a privilege,
    `log_admin_access()` (#1041 round-1 review), counts there.
    Bare privileged-field vocabulary (`role`, `permission`, `is_admin`, `scope`) is
    deliberately NOT treated as an auth signal — it would self-cancel against the exact
    field name the guard is flagging in the assignment line itself.

This guard is deliberately biased toward silence — any wiring that looks like a caller-
identity/authorization dependency suppresses it, even if the handler doesn't actually
check the field it's about to write. It surfaces the pattern for human review rather
than asserting the check is missing or insufficient.

Suppress an audited handler with `# security: allow-privileged-field-assignment`.

**Scope note:** distinct from `mass-assignment` (full `.dict()`/`.model_dump()` splat —
this guard needs a *named* privileged field, not a splat) and from `bola` (missing
ownership scoping on a *fetch* — this guard is about a *write* of a privileged field).
"""
from __future__ import annotations

import re
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import (
    AUTH_CALL_PRIVILEGED,
    AUTH_DEP_SIGNAL,
    PER_ROUTE_PRIV_FACTORY,
    CanaryPlant,
    Guard,
    blank_line_comments,
    cross_file_authed_routers,
    is_nonproduct_path,
    iter_files,
    iter_functions,
    pragma_present,
    python_scan_dirs,
    read,
    rel,
    route_deps_carry_auth,
    same_file_authed_routers,
)

_PRAGMA = re.compile(r"#\s*security:\s*allow-privileged-field-assignment")

_STANDARDS = ["OWASP:A01", "CWE-639"]

# `<var>` captures the router object the decorator is called on (last dotted segment) so a route
# authed by a router-level dependency (e.g. `include_router(admin.router, dependencies=[Depends(
# require_admin)])`) is recognized as privilege-checked.
_ROUTE_DECORATOR = re.compile(r"@\s*(?P<var>[\w.]+)\.(?:post|put|patch)\s*\(")

# The privileged field names this guard treats as an escalation vector.
_FIELD = r"(?:role|is_admin|is_staff|is_superuser|permissions?|scopes?|admin)"

# `<obj>.<field> = <body_var>.<field>` — the field name must match on BOTH sides
# (the assignment is literally copying the same-named privileged field through).
_ATTR_ASSIGN = re.compile(
    rf"\b\w+\.({_FIELD})\s*=\s*\w+\.\1\b", re.IGNORECASE,
)
# `setattr(<obj>, "<field>", <body_var>.<field>)`
_SETATTR_ASSIGN = re.compile(
    rf"""\bsetattr\s*\(\s*\w+\s*,\s*["']({_FIELD})["']\s*,\s*\w+\.\1\b""", re.IGNORECASE,
)

_AUTH_SIGNAL = re.compile(
    r"current_user|get_current_user|" + AUTH_DEP_SIGNAL +
    r"|\bSecurity\s*\(|require_admin|require_role|\b403\b|Forbidden",
    re.IGNORECASE,
)


class PrivilegedFieldAssignmentGuard(Guard):
    id = "privileged-field-assignment"
    title = "Privileged field written from request body with no caller-privilege check"
    area = "Login & access"

    # Canary plant: EXPECTS-ONLY — no `files`. The violation is planted in the canary's shared
    # `account_admin.py`, which several guards trip at once, so the file stays in `canary.py`'s
    # base owned by no guard. The ownership rule this follows is documented on `xxe_safe.py`.
    canary_plant = CanaryPlant(expects=frozenset({"privileged-field-assignment/unchecked-privilege-write"}))

    def applies(self, profile: StackProfile) -> bool:
        return "fastapi" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        files: list[tuple[Path, str]] = []
        seen: set[Path] = set()
        for d in python_scan_dirs(root, profile):
            for f in iter_files(d, (".py",)):
                if f in seen:
                    continue
                seen.add(f)
                # Skip non-product trees BEFORE building the list. This list feeds the
                # cross-file router resolver, so an unfiltered throwaway app in
                # `tests/test_admin.py` that mounts the router WITH auth marked the `admin` module
                # protected and silenced the finding on the production module of the same name.
                # An `old/` archive tree did the same (#473 review, HIGH 4).
                if is_nonproduct_path(rel(root, f), profile.archive_segments):
                    continue
                files.append((f, read(f)))

        # Pass 1 (repo-wide): a route file authed cross-file by a router-level admin dependency
        # (`main.py` doing `include_router(admin.router, dependencies=[Depends(require_admin)])`)
        # is privilege-checked at the router level — matched back by file stem. AUTH_CALL_PRIVILEGED, not
        # merely auth-named: this guard is about privilege ESCALATION, so a router-level
        # `Depends(get_current_user)` proves the caller is logged in and nothing more — it must not
        # silence a CRITICAL `user.role = body.role` write (#473 review §2).
        protected_routers = cross_file_authed_routers(files, auth_call=AUTH_CALL_PRIVILEGED)

        out: list[Finding] = []
        for f, text in files:
            out.extend(self._scan(root, f, text, protected_routers))
        return out

    def _scan(self, root: Path, f: Path, text: str, protected_routers: dict[str, set[str]]) -> list[Finding]:
        # Cross-file: every route in this file is authed at the router level if its module was
        # included-with-auth elsewhere (pass 1) — `routes/admin.py` <- `include_router(admin.router, ...)`.
        # Cross-file protection merges into the same-file router set below, PER ROUTER — NOT a
        # whole-file bail. Bailing on the file meant that in the standard public+admin layout (two
        # routers in one module, one mounted with auth and one without), mounting the admin router
        # with `Depends(require_admin)` silenced every route on its sibling (#473 review, HIGH 1).
        # Same-file: routers carrying a router-level `dependencies=` auth (construction or a bare-var
        # include in this file) gate every route on them. AUTH_CALL_PRIVILEGED — see the pass-1 note.
        authed_routers = same_file_authed_routers(text, auth_call=AUTH_CALL_PRIVILEGED, filename=f)
        authed_routers |= protected_routers.get(f.stem, set())

        out: list[Finding] = []
        for lineno, block in iter_functions(text, filename=f):
            # A real comment in the route block only, never the phrase in a string there (#1040).
            if pragma_present(_PRAGMA, block, dialect="python"):
                continue
            route = _ROUTE_DECORATOR.search(block)
            if route is None:
                continue
            if route.group("var").split(".")[-1] in authed_routers:
                continue
            m = _ATTR_ASSIGN.search(block) or _SETATTR_ASSIGN.search(block)
            if not m:
                continue
            if _AUTH_SIGNAL.search(block):
                continue
            # A privilege guard attached through the route's OWN `dependencies=[<factory()>]` list as
            # a bare returns-nothing call (`dependencies=[requires_system_write_role()]`). The PRIVILEGE
            # matcher, not the authentication one: a deps-list entry's return value is discarded, so
            # the handler never sees the caller and cannot check privilege itself, which makes the
            # slot the router level's equal. A bare `requires_authenticated()` there still fires,
            # as a router-level `Depends(get_current_user)` does (#872), and so does a call that
            # only names a privilege (`log_admin_access()`): the matcher wants a guard-shaped name.
            # `route.end() - 1` is the decorator's opening `(`.
            if route_deps_carry_auth(blank_line_comments(block), route.end() - 1, PER_ROUTE_PRIV_FACTORY):
                continue
            field = m.group(1)
            out.append(Finding(
                check_id=self.id,
                severity="critical",
                title=self.title,
                location=f"{rel(root, f)}:{lineno}",
                message=(
                    f"This route copies the privileged field `{field}` straight from the "
                    "request body onto a stored object, with no sign of checking the "
                    "*caller's own* privilege first — so any authenticated caller can send "
                    f'`"{field}": ...` in the JSON body and escalate their own or another '
                    "account's privilege (OWASP API5, Broken Function-Level Authorization; "
                    "CVE-2024-0795 was this exact shape)."
                ),
                remediation=(
                    "Check the caller's own privilege before writing a privileged field "
                    "(`if not current_user.is_admin: raise HTTPException(403)`), or drop the "
                    "field from the write-path entirely and set it through a separate "
                    "admin-only endpoint. A router-level admin dependency (same-file or a cross-file "
                    "`include_router(..., dependencies=[Depends(require_admin)])`) is already "
                    "recognized; suppress with `# security: allow-privileged-field-assignment` only "
                    "after confirming the privilege check happens elsewhere (e.g. inside a service "
                    "the guard can't see)."
                ),
                rule="privileged-field-assignment/unchecked-privilege-write",
                standards=list(_STANDARDS),
            ))
        return out
