---
type: Research
title: OWASP Noir — Endpoint Naming and Stale-Route Patterns
description: A naming-convention route-inventory pattern adapted from OWASP Noir's attack-surface-mapping concept for detecting debug/internal/legacy endpoints left reachable.
tags: [research, http, endpoints, owasp-noir]
timestamp: "2026-07-12T00:00:00Z"
---

# OWASP Noir — Endpoint Naming and Stale-Route Patterns

## What this covers

OWASP Noir builds a complete inventory of every endpoint a codebase registers — path, method,
params — across 50+ frameworks, on the premise that "shadow APIs, deprecated routes, and
undocumented handlers come out as part of the same inventory" as every other route. The
pattern below is a narrower slice of that idea: instead of a full inventory, it's a
naming-convention signal applied to each route's own path literal.

## A route's own name can flag it as non-production

Developers routinely leave a route reachable that was only ever meant to be temporary — a
`/debug/dump-config` route added to inspect state during an incident, an `/_internal/reset-
cache` admin shortcut wired up for a demo, an `/api/v0/legacy-export` kept "just in case" after
a v1 replacement shipped. None of these are marked non-public in any framework-visible way —
the framework serves them exactly like any other route — so they sit in production, often
undocumented and unmonitored, until someone finds the path. A route whose own path segment
names it `debug`/`backdoor`/`hidden`/`deprecated`/`legacy`/`staging`/`internal` is a strong,
cheap signal worth surfacing for human triage, even though the naming itself is not proof of
risk (a legitimate feature could be deliberately named `/legacy-importer`).

## Compound-word collisions are the dominant false-positive risk

Not every keyword behaves the same way as a naming signal. `internal` in particular is
ordinary product vocabulary in a way `debug`/`backdoor`/`legacy` are not — "internal notes,"
"internal comments," "internal review" are all legitimate business features, and a naive
substring or sub-token match on `internal` will flag `/users/{id}/internal_notes` as a
non-production route when it's actually an ordinary feature whose field happens to be named
"internal notes." The distinction that holds up: a keyword like `internal` should only match
when it constitutes the WHOLE path segment (`/internal/health`, `/_internal/reset-cache`,
after stripping marker underscores) — never as a sub-token of a longer compound business term.
Keywords that are not ordinary product vocabulary as qualifiers (`debug`, `backdoor`, `legacy`,
`deprecated`, `staging`, `hidden`) don't share this risk, so a sub-token match on those (
`/debug/dump-config`, `/legacy-api/v1`, `/__debug__/toolbar`) remains a low-noise signal.

## A naming signal is not proof of the underlying risk

Flagging a route by its name surfaces a candidate for review — it does not itself establish
that the route is unauthenticated, undocumented, or actually reachable in production. This
mirrors the same *presence vs. proof* distinction agentsec draws elsewhere for other
surfacing-only checks: the value is in cheaply narrowing a large route inventory down to the
handful worth a human actually looking at, not in asserting the finding is definitely
exploitable.

## Citations

- [owasp-noir/noir](https://github.com/owasp-noir/noir) — `src/analyzer/analyzers/python/fastapi.cr` (fetched and read directly), and the project's own README description of its shadow-API/deprecated-route inventory concept.
