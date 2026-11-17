"""Guard: NEXT_PUBLIC_-prefixed secret exposed in client bundle (OWASP:A02).

Next.js inlines every environment variable whose name starts with `NEXT_PUBLIC_` directly
into the client-side JavaScript bundle at build time — the exact same convention Vite
uses for its `VITE_` prefix (`vite_client_secret.py`), just under Next.js's own name.
Next.js is plausibly the single most common vibe-coding output framework (it's v0.dev's
default), and until this guard, agentsec had zero coverage for its equivalent of the same
mistake `vite-client-secret` already catches on the Vite side.

One statically-detectable signal:

  **`next-public-prefix-secret`** (HIGH): a line in a `.env*` file where the variable name
  starts with `NEXT_PUBLIC_` and the remainder of the name contains a word that
  conventionally indicates a secret value: SECRET, KEY, TOKEN, PASSWORD, PASS, CRED, or
  PRIVATE (case-insensitive). Examples that fire:

    NEXT_PUBLIC_SECRET_KEY=abc          # key starts right after the prefix
    NEXT_PUBLIC_API_TOKEN=xyz           # TOKEN anywhere after the prefix
    NEXT_PUBLIC_STRIPE_SECRET_KEY=sk_.. # SECRET, and it's a real Stripe secret key
    NEXT_PUBLIC_DB_PASSWORD=hunter2     # PASSWORD

  Variables that are legitimately `NEXT_PUBLIC_`-prefixed and do not indicate secrets are
  not flagged (a publishable/anon key is meant to ship to the browser):

    NEXT_PUBLIC_APP_NAME=MyApp                    # safe — no secret keyword
    NEXT_PUBLIC_API_URL=https://...                # safe — a URL is not a credential
    NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY=pk_...      # safe — publishable by design
    NEXT_PUBLIC_SUPABASE_ANON_KEY=eyJ...           # safe — anon key, gated by RLS

**Why HIGH?** Unlike a server-side secret leak (which requires an attacker to breach the
server), a bundled secret is readable by *every user* with a browser, requires zero
exploitation skill, and persists in caches and source maps after the variable is rotated
unless the CDN is purged.

**False-negative scope:** this guard only scans `.env*` files directly. Secrets set
through CI/CD platform UI, runtime injection, Vercel's own environment-variable dashboard,
or non-`.env` configuration mechanisms are NOT detected.

**Checklist item:** `6a-no-secret-in-nextjs-client-env`

**Suppress:** add a `# security: allow-next-public-client-secret` comment anywhere in the `.env` file
to silence this check for that specific file (e.g. when the "key" is a public
analytics write-only ingest token intentionally shipped browser-side). Document why in a
comment above the variable.
"""
from __future__ import annotations

import re
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import CanaryPlant, Guard, comment_dialect_for, iter_files_named, pragma_present, read, rel

_PRAGMA = "security: allow-next-public-client-secret"

_STANDARDS = ["OWASP:A02"]

# Matches lines where the key starts with NEXT_PUBLIC_ and the remainder of the name
# contains a word commonly used for secrets. Anchored to the start of a line to avoid
# matching values or comments. Exempt the public-by-design keys whose whole purpose is
# to ship to the browser: a `PUBLISHABLE` key (Stripe/Supabase) and the Supabase
# `ANON_KEY` (a `role:anon` JWT gated by RLS) — matched specifically, not a bare `ANON`,
# so a genuinely-secret var that merely contains "anon" still fires. Mirrors
# `vite_client_secret.py`'s `_VITE_SECRET` exactly, prefix swapped.
_NEXT_PUBLIC_SECRET = re.compile(
    r"^NEXT_PUBLIC_(?!.*(?:PUBLISHABLE|ANON_KEY))\w*(?:SECRET|KEY|TOKEN|PASSWORD|PASS|CRED|PRIVATE)\w*\s*=",
    re.IGNORECASE | re.MULTILINE,
)

def _is_env_file(p: Path) -> bool:
    """True if the file is a Next.js-style .env* file (by name, not suffix)."""
    name = p.name
    return name == ".env" or name.startswith(".env.")


class NextPublicClientSecretGuard(Guard):
    id = "next-public-client-secret"
    title = "NEXT_PUBLIC_-prefixed secret exposed in client bundle"
    area = "Secrets"

    # .env.development: NEXT_PUBLIC_-prefixed secret — fires next-public-client-secret.
    # (A separate env file from .env.local, which vite-client-secret already owns as its
    # canary plant — a shared file must be owned by exactly one declaration.)
    # next.config.js: existence alone is what makes detect() set the "nextjs" feature —
    # this guard owns planting it since it was the first Next.js-scoped guard built; the
    # sibling `next-api-route-auth-missing` guard's own applies() gate depends on this same
    # file existing in the combined canary tree, per one-file-several-guards' `expects`.
    # Must NOT contain: security: allow-next-public-client-secret (pragma silences guard).
    canary_plant = CanaryPlant(
        files={
            ".env.development": (
                "NEXT_PUBLIC_API_TOKEN=canary_placeholder_token_1234\n"
                "NEXT_PUBLIC_DATABASE_KEY=dbsecret456\n"
            ),
            "next.config.js": "module.exports = {};\n",
        },
        expects=frozenset({"next-public-client-secret/next-public-prefix-secret"}),
    )

    def applies(self, profile: StackProfile) -> bool:
        return "frontend" in profile.features or "nextjs" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:  # noqa: ARG002
        out: list[Finding] = []
        # A real `.env` is usually gitignored, so scan past .gitignore — but still skip
        # nested worktrees / vendored dirs (avoids dup findings from sibling checkouts).
        for f in iter_files_named(root, ".env*", respect_gitignore=False):
            if not _is_env_file(f):
                continue
            text = read(f)
            if pragma_present(_PRAGMA, text, dialect=comment_dialect_for(f)):
                continue
            for m in _NEXT_PUBLIC_SECRET.finditer(text):
                lineno = text.count("\n", 0, m.start()) + 1
                key = text[m.start():m.end()].rstrip("=").strip()
                out.append(
                    Finding(
                        check_id=self.id,
                        severity="high",
                        title=self.title,
                        location=f"{rel(root, f)}:{lineno}",
                        message=(
                            f"`{key}` is prefixed `NEXT_PUBLIC_`, which Next.js inlines "
                            "directly into the client-side JavaScript bundle at build "
                            "time — every user's browser receives the value, permanently, "
                            "in every deployed bundle and any CDN/browser cache until "
                            "purged. The variable name suggests a real secret, not a "
                            "public value."
                        ),
                        remediation=(
                            "Rename without the `NEXT_PUBLIC_` prefix so it stays "
                            "server-only (readable only in Server Components, Route "
                            "Handlers, and Server Actions), and read it via `process.env` "
                            "on the server, never passed to a Client Component as a prop. "
                            "If this value is genuinely meant to be public (a publishable "
                            "key, a public anon key gated by RLS), add "
                            f"`# {_PRAGMA}` above the line."
                        ),
                        rule="next-public-client-secret/next-public-prefix-secret",
                        standards=list(_STANDARDS),
                    )
                )
        return out
