---
name: security-scan-url
description: Security check for a deployed app when you have ONLY a live URL — no repo, no database credentials, no terminal history with the project. Use when the user asks to check/scan/audit a deployed site, a Lovable/Bolt/Replit/v0 app, or "my Supabase app," and does not have (or does not want to use) the source code.
---

# /security-scan-url

Every other `/security-*` skill assumes you have the repo checked out locally. This one is for
the shape that's actually common with Lovable/Bolt/Replit/v0-built apps: you have a live URL and
nothing else — often not even a terminal you're comfortable in. This skill runs the whole thing
for you; you only need to place one small file or DNS record when asked.

**What this checks:** whether the app's Supabase backend leaks data through its own public
anon key — the single most common real-world gap in this class of app (a May 2026 scan of
380,000 public Lovable/Base44/Replit/Netlify apps found ~5,000 with zero authentication, ~40%
of those leaking real data). It does **not** replace a full code audit (`/security-audit`) — it's
the outside-in check for exactly the population that can't run one.

## 1. Get the tool ready (you may need to run this once)

```bash
agentsec --version || pipx install ai-agent-security
```

If `pipx`/Python aren't available in this environment at all, say so plainly and stop here —
don't try to work around it. This skill needs the CLI installed somewhere it can run.

## 2. Ask for the URL, then get the ownership token

```bash
agentsec scan-live-url https://THEIR-APP-URL
```

This prints a token and two ways to prove you own the URL — explain both in plain language:

- **The file option (usually easier for this audience):** "Add a new file to your project at
  the path `.well-known/agentsec-verify.txt` containing exactly this text: `TOKEN`. If you're on
  Lovable/Bolt/Replit, ask it to add that file for you and deploy — most of these platforms
  publish static files automatically." This is why the file option exists at all: it works on
  any host, even one where the user has no DNS control whatsoever.
- **The DNS option** (only if they mention they manage their own domain/DNS): "Add a TXT record
  at `_agentsec-verify.THEIR-DOMAIN` with the value `TOKEN`."

Tell them to say "done" once it's live — DNS can take a few minutes to propagate; the file
option is usually near-instant once deployed.

## 3. Re-run with the token

```bash
agentsec scan-live-url https://THEIR-APP-URL --verify-token TOKEN
```

- **Ownership not verified:** tell them the exact reason printed (wrong content, not deployed
  yet, DNS not propagated) and offer to re-check in a minute rather than guessing at a fix.
- **No Supabase config found:** the app may not use Supabase, or the URL doesn't serve the
  client bundle directly (e.g. it's behind a redirect). Ask if they can give you the app's
  Supabase project URL and anon key directly — `--supabase-url` / `--supabase-anon-key` — both
  are meant to be public (the browser already has them), so this is not a secret they're
  handing you.

## 4. Explain the result in plain language

Read the report `agentsec scan-live-url` prints. For each finding:

- **Exposed tables:** "Your database currently lets anyone with your app's public key read the
  *names* of these tables: `X, Y, Z`. That doesn't necessarily mean the DATA in them is
  readable — but if any of those tables hold real user info and don't have Row-Level Security
  turned on, it probably is." Point them at turning on RLS for anything sensitive-sounding.
- **Public storage bucket:** "Your file storage bucket `X` is set to public — anyone who finds
  or guesses a file's path can download it, no login needed. Confirm that's intentional (it's
  fine for things like public logos/avatars, not fine for anything private)."
- **pg_graphql exposed:** "Your app also exposes a second, separate way to query your database
  (GraphQL) that isn't affected by the same protections as your main one. If you're not using
  this on purpose, ask your platform/AI assistant to disable it."

Never present a finding as "your data was stolen" — these are exposure findings (what CAN be
reached), not proof anything already was. Say that distinction plainly.

## 5. What this does not check

Say this explicitly so the user doesn't walk away over-confident: Edge Functions (no way to
find their names from outside), anything not behind Supabase, and the code-level checks
`/security-audit` covers (this never reads their source). If they later get access to the
code or a way to run it, point them at `/security-audit` next.
