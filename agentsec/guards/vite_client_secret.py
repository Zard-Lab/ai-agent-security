"""Guard: VITE_-prefixed secret exposed to the browser bundle (OWASP:A02).

Vite inlines every variable whose name starts with VITE_ directly into the
client-side JavaScript bundle at build time. That means any secret stored in a
VITE_-prefixed environment variable is:

  - Shipped to every browser that loads the app (the bundle is public)
  - Visible in browser DevTools → Sources / Network → any CDN cache
  - Recoverable by any user with `view-source:` or `strings` on the .js asset
  - Potentially scraped by automated credential harvesters

The pattern is a surprisingly common developer error because Vite intentionally
exposes VITE_ vars so React components can read process.env.VITE_* — the intent
is feature flags and public endpoint URLs, not secrets.

One statically-detectable signal:

  **`vite-prefix-secret`** (HIGH): A line in a .env* file where the variable
  name starts with VITE_ and the remainder of the name contains a word that
  conventionally indicates a secret value: SECRET, KEY, TOKEN, PASSWORD, PASS,
  CRED, or PRIVATE (case-insensitive). Examples that fire:

    VITE_SECRET_KEY=abc          # key starts right after VITE_
    VITE_API_TOKEN=xyz           # TOKEN anywhere after the prefix
    VITE_PRIVATE_KEY=rsa         # PRIVATE + KEY, both forbidden
    VITE_DB_PASSWORD=hunter2     # PASSWORD

  Variables that are legitimately VITE_-prefixed and do not indicate secrets
  are not flagged:

    VITE_APP_NAME=MyApp          # safe — no secret keyword
    VITE_API_URL=https://...     # safe — URL is not a credential

**Why HIGH?** Unlike a server-side secret leak (which requires an attacker to
breach the server), a bundled secret is readable by *every user* with a browser,
requires zero exploitation skill, and persists in caches and source maps after
the variable is rotated unless the CDN is purged.

**False-negative scope:** This guard only scans .env* files directly. Secrets
set through CI/CD platform UI, runtime injection, or non-.env configuration
mechanisms (e.g. Kubernetes secrets rendered into the build environment without
a .env file) are NOT detected.

**Checklist item:** `6a-no-secret-in-vite-client-env`

**Suppress:** add a `# security: allow-vite-client-secret` comment line anywhere in the .env
file to silence this check for that specific file (e.g. when the "key" is a
public analytics write-only ingest token that is intentionally browser-side).
Document why in a comment above the variable.
"""
from __future__ import annotations

import re
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import CanaryPlant, Guard, comment_dialect_for, iter_files_named, pragma_present, read, rel

_PRAGMA = "security: allow-vite-client-secret"

_STANDARDS = ["OWASP:A02"]

# Matches lines where the key starts with VITE_ and the remainder of the name
# contains a word commonly used for secrets. The pattern is anchored to the
# start of a line to avoid matching values or comments.
# Examples that match: VITE_SECRET_KEY=, VITE_API_TOKEN=, VITE_PRIVATE_KEY=
# Examples that do NOT match: VITE_APP_NAME=, VITE_API_URL=, SECRET_KEY=
# Exempt the public-by-design keys whose whole purpose is to ship to the browser: a
# `PUBLISHABLE` key (Stripe/Supabase) and the Supabase `ANON_KEY` (a `role:anon` JWT gated by
# RLS). `ANON_KEY` is matched specifically (not a bare `ANON`) so a genuinely-secret var that
# merely contains "anon" still fires.
_VITE_SECRET = re.compile(
    r"^VITE_(?!.*(?:PUBLISHABLE|ANON_KEY))\w*(?:SECRET|KEY|TOKEN|PASSWORD|PASS|CRED|PRIVATE)\w*\s*=",
    re.IGNORECASE | re.MULTILINE,
)

# .env file names that Vite loads: .env, .env.local, .env.production,
# .env.staging, .env.example, and any other .env.* variant.
_ENV_FILE_NAMES = frozenset({
    ".env",
    ".env.local",
    ".env.production",
    ".env.staging",
    ".env.example",
})


def _is_env_file(p: Path) -> bool:
    """True if the file is a Vite-style .env* file (by name, not suffix)."""
    name = p.name
    return name == ".env" or name.startswith(".env.")


class ViteClientSecretGuard(Guard):
    id = "vite-client-secret"
    title = "VITE_-prefixed secret exposed in client bundle"
    area = "Secrets"

    # .env.local: VITE_-prefixed secret — fires vite-client-secret.
    # .env.example already fires the same guard; this is a separate env file
    # to confirm the guard scans .env.local as well (belt-and-suspenders).
    # Must NOT contain: security: allow-vite-client-secret (pragma silences guard).
    # .env.local: VITE_API_TOKEN / VITE_DATABASE_KEY -> vite-prefix-secret.
    # (.env.example already fires this; .env.local confirms .env.* scanning.)
    canary_plant = CanaryPlant(
        files={
            ".env.local": (
                "VITE_API_TOKEN=sk_live_super_secret_key_1234\n"
                "VITE_DATABASE_KEY=dbsecret456\n"
            ),
        },
        expects=frozenset({"vite-client-secret/vite-prefix-secret"}),
    )

    def applies(self, profile: StackProfile) -> bool:
        return "frontend" in profile.features

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
            for m in _VITE_SECRET.finditer(text):
                # Compute 1-based line number for the match position.
                lineno = text[: m.start()].count("\n") + 1
                key = m.group(0).split("=")[0].strip()
                out.append(
                    Finding(
                        check_id=self.id,
                        severity="high",
                        title="VITE_-prefixed secret exposed in client bundle",
                        location=f"{rel(root, f)}:{lineno}",
                        message=(
                            f"`{key}` starts with VITE_ — Vite inlines all VITE_* variables "
                            "directly into the browser JavaScript bundle at build time. "
                            "The secret is shipped to every browser, visible in DevTools, "
                            "and recoverable from CDN caches. This is true even if the .env "
                            "file is not committed to version control: the secret is compiled "
                            "into the public asset at build time."
                        ),
                        remediation=(
                            "Move the secret to a server-side environment variable (no VITE_ "
                            "prefix). Access it only from your backend — expose a dedicated "
                            "API endpoint that the frontend calls instead of reading the secret "
                            "directly. If this is an intentionally public write-only token "
                            "(e.g. an analytics ingest key with no read permissions), add "
                            "`# security: allow-vite-client-secret` (a comment line) to the .env file and "
                            "document why above the variable."
                        ),
                        rule="vite-client-secret/vite-prefix-secret",
                        standards=list(_STANDARDS),
                    )
                )
        return out
