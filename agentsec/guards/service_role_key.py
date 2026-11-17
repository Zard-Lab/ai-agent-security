"""Guard: the Supabase service_role key must never reach client-facing code.

The `service_role` JWT **bypasses Row Level Security entirely** — it is the
database superuser of a Supabase app. The anon key is designed to ship in the
browser (RLS is the defense); the service_role key shipping in a client bundle
collapses every RLS policy at once: any visitor can read/write every tenant's
rows. This is the highest-impact single mistake in the stack, and it
complements `public-table-rls` / `definer-function-grants` (which assume the
attacker holds only the anon key).

Three client-side exposure shapes, all CRITICAL:

1. A client-bundled env var (``VITE_`` / ``NEXT_PUBLIC_`` / ``REACT_APP_``)
   whose name contains ``SERVICE_ROLE`` in a ``.env.example``/``.sample`` —
   the build inlines it into the served JS (mirrors the stripe guard's
   secret-in-client-env check).
2. A ``service_role`` reference in frontend code — there is no legitimate
   reason for client code to name the service-role key.
3. A hardcoded Supabase JWT literal in frontend code whose **decoded payload**
   says ``"role": "service_role"`` — the high-precision check: an ``eyJ…``
   literal alone may be the (legitimate) anon key, so we base64-decode the
   payload and only flag the service-role one.

Server-side use (Python backends) is the *correct* place for this key and is
never flagged. Suppress a known-safe client reference (e.g. a string in test
bait or docs tooling) with the inline pragma: ``// security: allow-service-role``.
"""
from __future__ import annotations

import base64
import re
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import CanaryPlant, Guard, comment_view, iter_files, read, rel, strip_js_comments

_CODE_SUFFIXES = (".ts", ".tsx", ".js", ".jsx")
_PUBLIC_SERVICE_ENV = re.compile(
    r"^[^\S\n]*(VITE_|NEXT_PUBLIC_|REACT_APP_)\w*SERVICE_?ROLE\w*\s*=", re.I | re.M
)
_SERVICE_ROLE_REF = re.compile(r"service_?role", re.I)
_JWT_LITERAL = re.compile(r"eyJ[A-Za-z0-9_-]{4,}\.(?P<payload>eyJ[A-Za-z0-9_-]{4,})\.[A-Za-z0-9_-]+")
_PRAGMA = "security: allow-service-role"
_STANDARDS = ["OWASP:A01", "OWASP:A02"]


def _is_supabase_edge_function(parts: tuple[str, ...]) -> bool:
    """True iff a repo-relative path runs through a ``supabase/functions/`` directory:
    Supabase Edge Functions (Deno, server-side), where the service_role key is correct."""
    return any(
        a == "supabase" and b == "functions"
        for a, b in zip(parts, parts[1:], strict=False)
    )


def _jwt_payload_is_service_role(payload_b64: str) -> bool:
    """True iff the JWT payload segment decodes to a service_role claim. Never raises."""
    try:
        decoded = base64.urlsafe_b64decode(payload_b64 + "=" * (-len(payload_b64) % 4))
        return b"service_role" in decoded
    except Exception:  # malformed/truncated token — not decodable, not a finding
        return False


class ServiceRoleKeyGuard(Guard):
    id = "service-role-key"
    title = "Supabase service_role key exposed client-side"
    area = "Login & access"

    # Canary plant: EXPECTS-ONLY — no `files`. The violation is planted in the canary's shared
    # `.env.example`, which several guards trip at once, so the file stays in `canary.py`'s
    # base owned by no guard. The ownership rule this follows is documented on `xxe_safe.py`.
    canary_plant = CanaryPlant(expects=frozenset({"service-role-key/client-env"}))

    def applies(self, profile: StackProfile) -> bool:
        return "supabase" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        return self._client_env(root) + self._frontend_code(root, profile)

    def _finding(self, loc: str, message: str, remediation: str, rule: str) -> Finding:
        return Finding(
            check_id=self.id, severity="critical", title=self.title, location=loc,
            message=message, remediation=remediation, rule=rule, standards=list(_STANDARDS),
        )

    def _client_env(self, root: Path) -> list[Finding]:
        out: list[Finding] = []
        env_files = {f for f in iter_files(root, (".example", ".sample")) if ".env" in f.name}
        env_files |= {p for p in (root / ".env.example", root / ".env.sample") if p.is_file()}
        for f in sorted(env_files):
            text = read(f)
            for m in _PUBLIC_SERVICE_ENV.finditer(text):
                lineno = text[: m.start()].count("\n") + 1
                out.append(self._finding(
                    f"{rel(root, f)}:{lineno}",
                    f"`{m.group(0).strip().rstrip('=')}` is a client-bundled env var carrying the "
                    "service_role key — the build inlines it into the served JS, and the "
                    "service_role key bypasses ALL Row Level Security.",
                    "Keep the service_role key server-side only (no VITE_/NEXT_PUBLIC_/REACT_APP_ "
                    "prefix); the client uses the anon key, with RLS as the boundary. Rotate the "
                    "key if it ever shipped.",
                    "service-role-key/client-env",
                ))
        return out

    def _frontend_code(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []
        fe = root / profile.frontend_dir if profile.frontend_dir else root
        for f in iter_files(fe, _CODE_SUFFIXES):
            raw = read(f)
            # Blank `//` and `/* */` comments (line numbers preserved) so a commented-out JWT
            # literal EXAMPLE doesn't fire (issue #424). The pragma itself lives in a comment, so
            # it is checked against the same-length COMMENT-ONLY view of the line below: a string
            # on that line quoting the pragma is content, not an opt-out (#424).
            view_lines = comment_view(raw, "js").splitlines()  # same length: comments only (#424)
            # When frontend_dir is unknown the fallback scans the whole repo, which sweeps
            # in supabase/functions/*.ts Deno EDGE functions. Those are server-side code where
            # REFERENCING SUPABASE_SERVICE_ROLE_KEY is the *correct* pattern, not a client
            # leak (#423), so the skip applies to that rule only, not to the whole file.
            #
            # As a `continue` at the top of the file loop it also suppressed the CRITICAL
            # jwt-literal rule, so a service_role JWT committed under `supabase/functions/`
            # yielded nothing while the byte-identical literal in `app.ts` yielded a CRITICAL
            # (#444 review). A hardcoded key is a committed secret wherever it sits: an edge
            # function is supposed to READ it from the environment, never embed it.
            is_edge_fn = _is_supabase_edge_function(f.relative_to(root).parts)
            for i, line in enumerate(strip_js_comments(raw).splitlines(), start=1):
                if _PRAGMA in view_lines[i - 1]:
                    continue
                jwt = next(
                    (m for m in _JWT_LITERAL.finditer(line)
                     if _jwt_payload_is_service_role(m.group("payload"))),
                    None,
                )
                if jwt:
                    out.append(self._finding(
                        f"{rel(root, f)}:{i}",
                        "A hardcoded Supabase JWT whose payload is `role: service_role` is "
                        "committed to source: it bypasses ALL Row Level Security for anyone who "
                        "can read the repository or the shipped bundle."
                        + (" An edge function must READ this key from the environment, never "
                           "embed it." if is_edge_fn else ""),
                        "Remove the literal and ROTATE the key immediately (it is public); the "
                        "client must only ever hold the anon key.",
                        "service-role-key/jwt-literal-in-frontend",
                    ))
                    continue
                if not is_edge_fn and _SERVICE_ROLE_REF.search(line):
                    out.append(self._finding(
                        f"{rel(root, f)}:{i}",
                        "Frontend code references the service_role key — there is no legitimate "
                        "client-side use; if the bundle can read it, so can every visitor, and it "
                        "bypasses ALL Row Level Security.",
                        "Move the privileged operation behind a backend endpoint that holds the "
                        "service_role key server-side. If this string is provably inert, suppress "
                        f"with `// {_PRAGMA}`.",
                        "service-role-key/reference-in-frontend",
                    ))
        return out
