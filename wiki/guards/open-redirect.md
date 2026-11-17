---
type: Guard
title: "open-redirect"
description: "No open redirect from user input."
timestamp: "2026-06-17T13:52:01+08:00"
guard_id: "open-redirect"
checklist_section: ["3a"]
standards: ["CWE-918", "OWASP:A01", "OWASP:A10"]
---

# No open redirect from user input

Flags a redirect sink whose target **provably derives from untrusted / request input**
(intra-file taint) and is not a `url_for(...)` call. Closes checklist item `3a-open-redirect`.
OWASP:A01 / CWE-601.

## The threat

`redirect(request.args.get("next"))` lets an attacker craft `?next=https://evil.example` and bounce a
victim off your trusted domain. Used for phishing (the link is on your domain, so it looks legitimate),
OAuth/token theft (a redirect after auth carries the code/token to the attacker's host), and to defeat
allow-list filters that only check the initial hostname. Sinks: Flask/Django `redirect(...)`,
Starlette/FastAPI `RedirectResponse(...)`, Django `HttpResponseRedirect(...)`.

## Exploitability rationale

MEDIUM. No direct server compromise, but a reliable phishing/credential-theft primitive and a common
OAuth-flow weakness. Unauthenticated-reachable, low skill to exploit; severity capped at medium because
impact is on the victim's session, not the server.

## What fires (taint, not pattern-presence)

The guard fires only when the redirect target is provably tainted by untrusted input:

- a **request accessor directly** in the target — `request.args/form/values/GET/POST/json/data/
  cookies/headers`, `.query_params`, or `self.request.…`;
- a **typed FastAPI/Starlette request-data parameter** — a `def` route parameter whose default is a
  `Query()/Path()/Body()/Form()/Cookie()/Header()/File()` marker, or whose `Annotated[...]` metadata
  carries one: `def go(next: str = Query(...)): return RedirectResponse(next)`. Such a parameter *is*
  request input even though it never appears as `next = request.X` (issue #296 — the most common
  FastAPI redirect-target source, and a regression the taint rewrite silently introduced). Recognition
  is **gated on the marker name actually being bound to a fastapi/starlette import** in that file —
  resolved with real import semantics via `ast` (aliases like `Query as Q`, import order /
  last-binding-wins, `;`-chained and parenthesized/`\`-continued imports all handled), so a
  `pathlib.Path(...)` or SQLAlchemy `Query(...)` default — same spelling, different origin — is not
  misread as a request binding (#296 review rounds 5-6);
- a **tainted variable** — a name assigned (anywhere in the same file, transitively) from such an
  accessor / marker param: `nxt = request.args.get("n"); redirect(nxt)`;
- an **f-string / concat that carries one** — `redirect(f"{request.args['n']}")`,
  `redirect("/go?" + request.args.get("u"))`.

This replaced the earlier *pattern-presence* model (issue #90), which fired on any "dynamic" target
including a **bare variable** — that shipped low-confidence noise on essentially any Python repo,
contradicting the F2/B8 auto-exclude-noise doctrine, and *also* missed a direct
`redirect(request.args.get('next'))` (the quoted key made it look non-dynamic).

## When NOT to flag (and the pragma)

- `redirect(dest)` where `dest` is a **plain** function param / internal value (no request-data marker,
  not request-derived) → silent. (A `dest: str = Query(...)` marker param DOES fire — see above.)
- `target = url_for("dashboard"); redirect(target)` and `redirect(url_for("dashboard"))` → silent.
  Every `url_for(...)` **call span** is blanked before the target is judged, so untrusted input *inside*
  its args (a vetted internal path) and a transform on the result (`redirect(url_for(...).lower())`) both
  stay silent, while untrusted that survives **outside** a url_for call — a concatenation
  (`redirect(url_for("x") + request.args["n"])`) — **fires**.
- `redirect("/home")` and other literal paths → silent.
- `redirect(f"/user/{uid}")` built from an internal value → silent.
- Commented-out lines → silent.
- An audited-safe case (target validated upstream) → suppress with `# security: allow-open-redirect`.

The redirect target is read from the sink call's **first positional argument plus any `url`/`to`/
`location`/`redirect_to` keyword argument** (bracket-aware extraction), so a target passed out of order
or by keyword — `RedirectResponse(status_code=302, url=request.query_params["n"])` — is not missed.

## Lexing (why strings/comments/f-strings are handled correctly)

The file is tokenized with the stdlib `tokenize` module and the character spans of every string
literal and comment token are blanked before analysis. So a request accessor or a `redirect(...)`
sink that appears only as *text* — inside a string, a comment, a log message, or a multi-line
docstring code-example — is never mistaken for code, while f-string **interpolations**
(`f"{request.args['n']}"`, incl. nested format-spec fields `{v:>{w}}`) are preserved as the code they
are. This replaced a line-and-regex lexer that repeatedly leaked at these boundaries (issue #90,
review rounds 1-3). On a syntactically invalid file it degrades to a best-effort raw scan (never
raises).

## Known bypasses (honest limits)

- **Cross-file / cross-function taint.** Taint is tracked intra-file only; a target tainted in a
  different function or module is not followed (false negative).
- **Unrecognized accessor / marker.** `_UNTRUSTED` lists explicit request accessors and `_MARKERS` the
  FastAPI request-data marker names (resolved to their imported bindings via AST); a framework accessor or
  marker not in the lists (e.g. `request.referrer`, a custom wrapper, `Depends`-injected values) is not
  treated as untrusted — broaden the set/regex if needed.
- **Plain unmarked route param.** FastAPI treats a bare `def go(next: str)` param as an implicit query
  param, but the guard **intentionally** does not taint an unmarked param — that is indistinguishable
  from an internal helper param and tainting it would reintroduce the #90 F2/B8 false positive. Only an
  explicit request-data marker (`Query`/`Path`/`Body`/…) or a `request.` accessor seeds taint.
- **Module-qualified marker.** `import fastapi` then `def go(x = fastapi.Query(...))` is not
  recognized — the param-default match keys on a bare `Name(...)` call, not a dotted `mod.Name(...)`.
  The near-universal `from fastapi import Query` form (incl. `as`-aliases, resolved via `ast`) is
  covered; the dotted form is a residual false negative.
- **Multi-line calls.** The sink→argument match is per physical line; a redirect whose sink and
  untrusted target sit on different lines is not matched. (Multi-line *strings* ARE handled — see
  Lexing above — this limit is only about a call split across lines.)
- **Indirect sinks.** A framework-specific redirect helper or a hand-built `Response(status=302,
  headers=...)` is not matched.
- **Pathologically long single line (performance, not correctness).** The taint fixpoint and the
  `url_for` blanking are both linear, and the guard is linear on realistic code (thousands of redirect
  statements across separate lines scan in well under a second). The one residual super-linear cost is
  stdlib `tokenize` in `_blank_strings_and_comments`, which is ~O(n²) in tokens on a *single* physical
  line — so a lone artificial line packing thousands of calls takes a few seconds. Spreading the same
  tokens across lines tokenizes linearly; real source never hits this. It never hangs or raises.
- **Validated-upstream taint.** `nxt = sanitize(request.args["n"]); redirect(nxt)` still fires (taint
  flows through the assignment) — pragma covers the audited-safe case; the cost of catching the
  unvalidated one.
- **Walrus in a discarded sub-expression.** `total = 1 if (x := request.args["n"]) else 0; redirect(total)`
  fires though `total` is only ever `0`/`1` — the assignment's value textually contains a request accessor,
  so `total` over-taints. Consistent with the guard's "over-tainting only ever makes it fire" stance (a
  false positive, never a miss); pragma silences an audited case.

## What this guard does NOT prove

It flags a redirect target that provably derives from untrusted input in the same file; it does not
prove the value reaches the sink unsanitized, nor that a silent case is safe. Absence of a finding ≠
provably-free of open redirect — an allow-list on redirect targets is still the control.

# Citations

[1] agentsec checklist item `3a-open-redirect` (§3a)
[2] CWE-918
[3] OWASP:A01
[4] OWASP:A10
