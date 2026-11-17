"""Guard: Supabase `pgmq` queue exposed via the Data API (checklist §7 — Database Security).

`pgmq` (Postgres Message Queue) is Supabase's built-in queueing extension. Its queue
tables live in the `pgmq` schema (`pgmq.q_<queue_name>`), which is never itself part of
the PostgREST Data API — but Supabase ships a companion `pgmq_public` schema of thin
wrapper views/functions specifically so a queue CAN be reached over the Data API. Adding
`pgmq_public` to the exposed API schema list is a deliberate, one-line opt-in — and it is
also the entire exposure: once `pgmq_public` is reachable, any caller holding the `anon`
or `authenticated` key can read, send, and pop messages through `/rest/v1/`, since the
queue tables underneath are not RLS-scoped the way an application table would be.

Mirrors Supabase Splinter's `insecure_queue_exposed_in_api` lint, adapted to what a
static scanner can actually see. Splinter's own version runs against a live database and
checks `has_table_privilege('anon'/'authenticated', ...)` directly on `pgmq.q_*` tables —
this guard instead reads the one artifact that actually decides Data-API exposure without
a live connection: the project's own `supabase/config.toml`.

**Detection:** parse `supabase/config.toml` (or any `config.toml` whose content shows the
Supabase CLI shape — an `[api]` table) and check whether its `schemas` array (under `[api]`)
lists `pgmq_public`. If it does, the finding fires — there is no secondary "but is RLS
enabled" branch to check, because `pgmq_public`'s wrapper objects are exactly the API
surface Supabase created to make an otherwise-internal schema queryable, and pgmq queue
tables are not designed to carry per-row RLS policies the way a normal `public` table is.

**What this does NOT do:** it does not verify that any queue actually exists
(`pgmq.create(...)` calls are not scanned) — the config line alone is the complete,
sufficient signal, since exposure is controlled entirely at the schema-list level, not
per-queue. It also does not scan for the SQL-GRANT-shaped alternative some projects might
use instead of the CLI config; that is a documented, narrower scope, not an oversight.

**Suppress:** add `# security: allow-pgmq-queue-exposed` as a `config.toml` comment line.
"""
from __future__ import annotations

import tomllib
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import CanaryPlant, Guard, iter_files, pragma_present, read, rel

_PRAGMA = "security: allow-pgmq-queue-exposed"
_STANDARDS = ["OWASP:A01"]
_EXPOSED_SCHEMA = "pgmq_public"


class PgmqQueueExposedInApiGuard(Guard):
    id = "pgmq-queue-exposed-in-api"
    title = "Supabase pgmq queue exposed via the Data API"
    area = "Database"

    # supabase/config.toml: [api] schemas includes "pgmq_public" -> fires
    # pgmq-queue-exposed-in-api/schema-exposed (HIGH).
    canary_plant = CanaryPlant(
        files={
            "supabase/config.toml": (
                "[api]\n"
                'schemas = ["public", "pgmq_public"]\n'
            ),
        },
        expects=frozenset({"pgmq-queue-exposed-in-api/schema-exposed"}),
    )

    def applies(self, profile: StackProfile) -> bool:
        return "supabase" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []
        for f in iter_files(root, (".toml",)):
            if f.name != "config.toml":
                continue
            raw = read(f)
            if not raw or pragma_present(_PRAGMA, raw, dialect="hash"):
                continue
            try:
                data = tomllib.loads(raw)
            except (tomllib.TOMLDecodeError, UnicodeDecodeError):
                continue
            api = data.get("api")
            if not isinstance(api, dict):
                continue
            schemas = api.get("schemas")
            if not isinstance(schemas, list) or _EXPOSED_SCHEMA not in schemas:
                continue
            out.append(
                Finding(
                    check_id=self.id,
                    severity="high",
                    title=self.title,
                    location=rel(root, f),
                    message=(
                        f"`[api] schemas` in {rel(root, f)} includes `{_EXPOSED_SCHEMA}`, "
                        "which exposes every pgmq message queue in this project to the "
                        "Data API. Any caller holding the `anon` or `authenticated` key can "
                        "read, send, and pop messages through `/rest/v1/` — pgmq queue "
                        "tables are not designed to carry per-row RLS the way an "
                        "application table is, so this is direct queue access, not a "
                        "gated one."
                    ),
                    remediation=(
                        f'Remove `"{_EXPOSED_SCHEMA}"` from `[api] schemas` unless the '
                        "queue is genuinely meant to be client-reachable. If it must be "
                        "exposed, put a scoped wrapper function in front of it that "
                        "enforces per-caller authorization rather than exposing the raw "
                        "queue views directly. Intentional and reviewed? add "
                        f"`# {_PRAGMA}` as a comment in this file."
                    ),
                    rule="pgmq-queue-exposed-in-api/schema-exposed",
                    standards=list(_STANDARDS),
                )
            )
        return out
