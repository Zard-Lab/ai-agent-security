---
type: Guard
title: "client-side-secret-literal"
description: "Hardcoded provider API-key / secret literal in client-side JavaScript."
timestamp: "2026-11-04T00:00:00Z"
guard_id: "client-side-secret-literal"
checklist_section: ["6a"]
standards: ["OWASP:A02"]
---

# Hardcoded provider API-key / secret literal in client-side JavaScript

_Dean — 2026-07-22_

---

## The threat

Wiz's "From Prompts to Production" (2026), user-risk #2: vibe-coded apps hardcode a third-party secret
into client JavaScript. **Who reaches it:** any visitor. **With what privilege:** none — the value ships
in the bundle. **To what effect:** the attacker reads the live key from devtools and spends against it
(an OpenAI key = billed inference / Denial-of-Wallet) or pivots with it (an AWS `AKIA…`, a GitHub
`ghp_…`, a Slack token). Findings carry **OWASP:A02** (Cryptographic Failures — credential exposure) and
**CWE-798** (Use of Hard-coded Credentials).

## Why it's often introduced

An AI generator wires a third-party API call directly from the React client because it is the shortest
path to "it works" — the model has no notion that `import.meta.env` and inline constants are inlined into
the public bundle. The Wiz anonymized example:

```js
const h = "sk-proj-FSAFCREDACTEDOVY7EfDD-XIMrVayZub7TakA";
localStorage.setItem("openai_api_key", h);
```

On the FastAPI + React + Supabase stack the fix is a backend proxy (a Supabase Edge Function or a FastAPI
route) that holds the key server-side; the client calls that endpoint, never the third party directly.

## Detection design

1. **applies()** — any of `frontend`, `javascript` or `typescript`. The gate has to accept every
   feature the scanned suffixes can produce: `detect.py` sets `javascript` only for `.js/.jsx` and
   `typescript` for `.ts/.tsx`. Before #1082 the gate omitted `typescript`, so a TS-only repo (an
   Express/Nest/MCP backend, or an Angular frontend with no react/vite `package.json`) was never
   scanned. Whether a TS backend's committed key failed `--guards-only` (the pre-commit hook)
   depended on an unrelated `.js` file such as `eslint.config.js` existing. **Backend `.ts` is
   therefore in scope**, which makes this guard the JS/TS half of `hardcoded-llm-provider-key`
   (`.py`/`.go`), not strictly a client-side check. The HIGH finding is side-aware. A repo reached
   only through `typescript` (no `frontend`, no `javascript`) gets a "committed in JavaScript/TypeScript
   source" message, a matching title, and a remediation that says to read the key from a secret
   manager or server env var and purge it from history, instead of "ships to every visitor" and
   "proxy it through a backend" (advice a backend file cannot take). Every profile that fired before
   #1082 keeps the original title, message and remediation byte-for-byte, a `javascript`-only
   backend included, because `Finding.fingerprint()` hashes `message[:120]` and rewording it would
   orphan existing baselines and triage verdicts. The widening also brings the
   `AKIA`/`ghp_`/`glpat-`/Slack/Twilio rules to TS-only repos; those are committed credentials on
   either side.
2. **Files scanned** — `.js/.jsx/.ts/.tsx` via `iter_files`. A genuine test/fixture/example path
   (`is_nonproduct_path`) is still scanned, not skipped — a match there is **downgraded to
   `medium`** rather than dropped (added after the first review round): most keys under
   `tests/`/`fixtures/`/`examples/` really are deliberately fake, but "usually" is not "always", a
   real key pasted into a fixture during debugging is still a live leak, and a silent skip cannot
   be told apart from "no key in this file at all" — the exact same "downgrade, not suppress"
   reasoning already applied to the public-browser-key allowlist below (#488 B3), now applied
   consistently to this second suppression mechanism in the same guard, but at a different target
   severity: `medium`, not `info` — this key LOOKS real and failed the public-key allowlist,
   it's just possibly-fake by path convention, so it should stay gateable by a repo that opts into
   `--fail-on medium` (one of the three values the action's `fail-on` input, `action.yml`, accepts;
   `low` is not, so a `low` downgrade would have been un-gateable through the action at ANY
   setting — decided explicitly on PR #583's review). Comments blanked via
   `strip_js_comments` so a documented example key in a note never fires. Bundled JS under
   `dist/`/`build/` is out of the walk surface (the common case is the committed *source*).
3. **Pattern** — `_PROVIDER_KEY`: a token matching a high-confidence provider prefix with a long,
   key-shaped body, left-boundaried (`(?<![A-Za-z0-9_])`) so `myAKIA…` does not match: `sk-proj-`/
   `sk-ant-` + `{20,}`, `AKIA` + 16 upper-alnum, `gh[posur]_` + 36, `AIza` + 35, `glpat-` + 20,
   Slack `xox[baprs]-` anchored to its real structure (two/three `[0-9]{9,}` numeric-ID groups then a
   `[0-9A-Za-z]{20,}` secret) so a word-slug like `xoxp-not-a-real-token` does not match, `SK` + 32
   lowercase alnum (Twilio), and a Slack incoming-webhook URL (`hooks.slack.com/services/T…/B…/…`).
   Bare `sk-` is deliberately excluded (collides with BEM/skeleton class names); a bare Heroku-style
   UUID and generic `secret`/`api_key` patterns were considered (eslint-plugin-no-secrets research,
   candidate list) and deliberately NOT ported — both are far too collision-prone for this guard's precision
   bar (a UUID alone matches routine, non-secret identifiers constantly). Zero entropy analysis by
   design — the prefixes are specific enough to stay low-FP. Findings are emitted via `finditer` (not
   `search`) and name the provider, so two distinct-provider keys on one line surface as two findings.

   **(2026-11-04, trufflehog cross-check)** mirrored the same 5-provider widening made to
   this guard's Python/Go sibling `hardcoded-llm-provider-key`: Pinecone (`pcsk_` + 5-6 alnum + `_` +
   63 alnum), Replicate (`r8_` + 37 alnum/dash/underscore), Groq (`gsk_` + 52 alnum), LangSmith
   (`lsv2_pt_`/`lsv2_sk_` + 32 hex + `_` + 10 hex), and a Supabase personal access token (`sbp_` + 40
   lowercase-alnum — distinct from the service-role/anon JWT keys this stack's RLS guards already
   cover, since a PAT authenticates the Supabase management API itself).
4. **Pragma** — a `// security: allow-client-side-secret` comment anywhere in the file (a string literal
   quoting the phrase does not count, #424).
5. **Severity / rules / standards** — three rules, all `["OWASP:A02", "CWE-798"]`:
   `client-side-secret-literal/hardcoded-api-key-literal` (**high**) for a non-Google provider secret,
   `client-side-secret-literal/google-key-not-public` (**high**) for an `AIza…` the allowlist
   **refused**, and `client-side-secret-literal/public-browser-key` (**info**) for an `AIza…` the
   allowlist below identifies as a public Firebase/Maps browser key. The Google high path has its own
   rule id purely so the canary can see the allowlist widening — severity, message and remediation are
   identical to the generic high (#488 re-gate, F3). The allowlist **downgrades, it does not drop**:
   a silent skip cannot be distinguished from "no Google key here", and an allowlist is exactly the
   judgment a reader should be able to audit. `info` sits below the default `--fail-on high` gate.
   Both rules carry `path:line:col` (the column keeps two keys on one line at distinct fingerprints).

## When NOT to flag

A short `sk-` fragment or a hyphenated class (`"sk-loading-spinner-container"`) has no key-shaped body —
silent. An identifier ending in a prefix (`myAKIAHelper`) fails the left boundary — silent. A Slack-prefixed
word-slug (`"xoxp-not-a-real-token-just-a-css-slug"`) lacks the numeric-ID structure — silent. A `.env`
`VITE_*` secret name belongs to `vite-client-secret`; PEM key material belongs to
`hardcoded-private-key-in-source` — neither double-fires here. Use the pragma for a confirmed fake/fixture
value the linters don't already exclude — a test/fixture path alone is no longer sufficient to silence a
finding: it fires at `medium` instead of `high`, not silently.

**Documented placeholder keys are not excluded.** This guard has no token-level placeholder check
(unlike `hardcoded-llm-provider-key`), so AWS's documentation key `AKIAIOSFODNN7EXAMPLE` fires HIGH
in a product path, the same as a real key. That has been true under `javascript` all along, and
#1082 extends it to TS-only repos, `.d.ts` declarations included. It is recorded as accepted rather
than narrowed in the #1082 fix: the existing tests use that very literal as a positive. Use the pragma
for a file that legitimately carries it.

**Public browser keys are downgraded to `info`, not reported HIGH.** A Firebase web `apiKey` and a
Google Maps JS browser key have exactly the `AIza` + 35 shape, and Google documents both as non-secret
and REQUIRED in client code — the key identifies the project, and access is controlled by API-key
restrictions and Firebase Security Rules, not by secrecy. Reporting them HIGH with "rotate the exposed
key immediately" gave every React+Firebase app an unfixable finding in a CI gate (#488 review), the
same class the round-2 backlog's public-OAuth-client-ID allowlist addresses.

### The allowlist invariant

> An `AIza…` token may be downgraded only when something actually **identifies** it as Google's
> documented public browser key — a **host+path**, a **name that asserts which side it lives on**, or
> the token's **own enclosing structure**. Never a topical word, an import, or a neighbouring
> statement in a line window.

The corollary is the part this guard kept getting wrong: *an allowlist that reads the neighbourhood
spares the neighbourhood, not the identifier*. Both fail-open regressions on this branch were a
±6-line window standing in for evidence about the key itself (#488 review B3, then #488 independent
gate H1/H2).

Four accepted shapes, of deliberately different strictness because they carry different evidence:

| shape | example | what corroborates it |
|---|---|---|
| the Maps **JavaScript API** script URL | `https://maps.googleapis.com/maps/api/js?…&key=AIza…` | nothing further — the authority host **and** the `/maps/api/js` path identify a browser-only endpoint. The host+`key=` must sit in one unbroken URL token (no quote/backtick/space between) and the host must be the URL's authority (`//maps.googleapis.com/…`) |
| a **browser-explicit** binding name | `googleMapsApiKey`, `NEXT_PUBLIC_FIREBASE_API_KEY`, `VITE_FIREBASE_API_KEY` | a weak topical context word (`firebase`, `places`, `geocod`, …) in ±6 lines. The bundler-public prefixes are compiled into the bundle *by definition*, and `googleMapsApiKey` is `useJsApiLoader`'s own prop — the name asserts the side |
| the **ambiguous** `GOOGLE_MAPS_API_KEY` | `const GOOGLE_MAPS_API_KEY = "AIza…"` | a **structural** marker (`@react-google-maps`, `maps.googleapis`, `useJsApiLoader`, `new Loader(`, `initializeApp`, `firebase/`, `getFirestore`, `@googlemaps/`) in ±6 lines. Without a public prefix this name is equally the convention for a **server-side** Geocoding / Places-Web-Service key |
| the **generic** `apiKey` / `api_key` | `{ apiKey: "AIza…", authDomain: … }` | a Firebase sibling field (`authDomain`, `projectId`, `appId`, …) or a structural marker **in the token's own enclosing expression** — the innermost two bracket levels plus the callee in front of them, so `initializeApp({ apiKey })` and `new Loader({ apiKey })` qualify and a top-level `const apiKey = …` has only its own line to vouch for it |

A bare `AIza…` with no such identification — a server-side Google API key pasted into client JS — still
fires HIGH. `getAuth(` is deliberately **not** structural evidence: it is Clerk's and NextAuth's
spelling at least as often as Firebase's.

**Residuals, both directions (measured, accepted):**

- *fail-closed:* a Firebase config object carrying **only** `apiKey` and no sibling field
  (`const firebaseConfig = { apiKey: "AIza…" }`) fires HIGH — nothing in the expression identifies it,
  and Google's own snippet always ships 5-6 fields. Widening to the assignment-target name would
  reintroduce a name-shaped blanket, so it is left fail-closed; use the pragma.
- *fail-open:* a non-Firebase object that happens to pair `projectId` with `apiKey` (a GCP-ish config)
  is downgraded — `projectId` is Firebase's own field name, so the two are not separable by shape.
- *fail-open:* a genuinely secret Google key placed **inside** a real Firebase config object, under the
  `apiKey` field, is indistinguishable from the public one and is downgraded.
- *bounded scan:* the bracket walk is capped at `_MAX_SCOPE_CHARS` (4000) in each direction. This is
  **not** O(1) per match — `_enclosing_expression` joins the file on every call, so per-match cost still
  rises with file size (measured; the earlier claim here was wrong — #488 re-gate, F5). What the cap buys
  is the pathological shape. The structure view is built ONCE PER FILE, not per match — building it
  per match made the scan super-linear (2000 matches took 16s; re-gate M1). Measured after the fix:
  400 `apiKey` fields 0.118s, 2000 fields 0.545s.
  Hitting the cap yields a **narrower** scope, so it fails closed — `_statement_slice` is what makes that
  true, since the previous whole-line fallback could be *wider* than the bracket scope (F2).
  `_enclosing_expression` is total: a negative or past-the-end index/column is clamped and an unbalanced
  bracket just narrows the slice (`test_enclosing_expression_is_total`,
  `test_enclosing_expression_clamps_negative_index`).
- *fail-closed:* more than `_SCOPE_LEVELS` (2) of nesting never reaches the callee, so
  `initializeApp({ a: { b: { apiKey: "AIza…" } } })` stays HIGH (#488 re-gate, F9). Correct direction,
  recorded so it is not rediscovered as a bug.
- *scope is the STATEMENT, not the line:* at top level the corroboration scope is the token's own
  statement. A neighbouring statement sharing the line (`const cfg = {...}; const apiKey = "AIza…"`)
  must not vouch for it — that was H2's failure mode at line granularity (#488 re-gate, F4,
  `test_same_line_neighbouring_statement_does_not_corroborate`).
- *the guard does not lex JavaScript:* structure for both scope walks comes from
  `guards/base.py::strip_js_comments(src, strip_strings=True)` — offset-preserving, and it already
  models regex literals and template literals. The walks read that blanked view; the slice is taken
  from the REAL source. Three consecutive rounds of hand-rolled scanning each reopened the same
  fail-open on the next unmodelled construct — a brace inside a string (fixup gate C1), a quote
  inside a `/…/` regex, then an unterminated backtick masking to EOF (re-gate C1/C2) — so the guard
  stopped owning lexical analysis rather than adding a fourth rule.
- *structure from the blanked view, CONTENT from the real source:* this split is load-bearing in both
  directions. Reading structure from the real source lets a brace in a string move the depth;
  reading content from the blanked view would delete quoted object keys, and `{ "authDomain": … }`
  is ordinary JavaScript — every legitimate Firebase config would stop corroborating its own key and
  fire HIGH, the unfixable-CI-finding class this guard exists to avoid. Pinned by
  `test_lexical_constructs_cannot_widen_the_scope` and `test_quoted_object_keys_still_corroborate`.
- *a prefix asserts the SIDE, not the sensitivity:* `VITE_SECRET_API_KEY` holding a real server key is
  spared. The developer has both leaked it into the bundle and told this guard it is public, and the
  name cannot separate those two. Inherent to the prefix rule above; pinned by
  `test_bundler_public_prefix_residual_a_prefixed_secret_is_spared` so a change to it is deliberate
  (#488 fixup gate, M1).
- *bundler-public names are a PREFIX RULE:* any `(NEXT_PUBLIC|REACT_APP|VITE|PUBLIC|GATSBY|EXPO_PUBLIC)_*API_KEY`
  asserts the client side. It was an enumeration of exact names, which made the verdict depend on which
  bundler the app used — `VITE_GOOGLE_MAPS_API_KEY` fired HIGH while `NEXT_PUBLIC_GOOGLE_MAPS_API_KEY`
  did not (#488 re-gate, F1, `test_bundler_public_prefix_is_a_rule_not_an_enumeration`).

**Provider labels are per-provider.** `sk-proj-` maps to OpenAI and `sk-ant-` to Anthropic, not to one
combined label. Two distinct leaked keys on the same line share the `file:lineno` location, so a shared
label made their messages byte-identical and collapsed them to one fingerprint — waiving one waived the
other (#488 review).

**Known false-positive class (accepted, zero-entropy trade-off):** the Google alternative `AIza` + 35
shares the base64url alphabet (`[0-9A-Za-z_-]`), so a base64url blob — most commonly a JWT segment
embedded in client JS — that happens to contain the literal `AIza` followed by 35 more base64url chars
collides. It is narrow (needs the 4-char `AIza` to land, ~1/62⁴ per position) and is the industry-standard
Google-key shape (matches `gitleaks`' default rule), so it is left as-is rather than tightened; a standard
(`+/`-alphabet) base64 data URI does not collide. The `// security: allow-client-side-secret` comment is the
escape hatch if it ever fires on a real JWT.

## Tests

| Test | What it checks |
|---|---|
| `test_client_side_secret_literal_fires_openai_project_key` | `sk-proj-…` literal → high finding |
| `test_client_side_secret_literal_fires_aws_and_github` | `AKIA…` + `ghp_…` both fire |
| `test_client_side_secret_literal_fires_google_key` | `AIza…` fires |
| `test_firebase_web_config_key_does_not_fire_high` | FP-bait (#488): a Firebase web `apiKey` in its config object is a public project id |
| `test_google_maps_browser_key_does_not_fire_high` | FP-bait (#488): a Maps JS browser key in a `Loader({...})` |
| `test_bare_google_api_key_still_fires` | the other direction: an `AIza…` with no Firebase/Maps wiring is still a leak |
| `test_openai_and_anthropic_keys_are_distinct_findings` | FN-guard (#488): two keys on one line keep two fingerprints |
| `test_unrelated_server_key_near_a_firebase_config_still_fires` | FN-guard (B3): proximity alone must not exempt |
| `test_firebase_config_alone_is_info_not_high` / `test_maps_browser_key_is_info` | the downgrade contract: disclosed, never HIGH |
| `test_generic_apikey_name_near_a_topical_word_still_fires_high` | FN-guard: a topical word in **code** (never a comment — `run()` strips comments before the window is built, so a comment fixture pins nothing) does not corroborate `apiKey` |
| `test_maps_script_url_key_is_info_not_high` | the `?key=` script-URL shape is a browser key |
| `test_non_google_url_with_a_key_param_still_fires_high` | FN-guard (H1): `?key=` on a non-Google host is not the Maps URL |
| `test_geocoding_web_service_key_still_fires_high` | FN-guard (H1): Google's own **server-side** Geocoding Web Service URL |
| `test_maps_js_path_as_a_query_value_still_fires_high` | FN-guard (H1): the path as a query *value* of another host |
| `test_server_key_below_a_firebase_config_is_not_blanketed` | FN-guard (H2): a neighbouring config object does not vouch |
| `test_server_key_below_a_lone_firebase_import_still_fires_high` | FN-guard (H2): a file-level import does not vouch |
| `test_clerk_getauth_does_not_corroborate_a_google_key` | FN-guard (H2): `getAuth(` is Clerk's spelling too |
| `test_screaming_snake_maps_key_on_a_topical_word_alone_fires_high` | FN-guard (H7): `GOOGLE_MAPS_API_KEY` names the product, not the side |
| `test_two_public_browser_keys_on_one_line_are_distinct_findings` | FN-guard (H5): the `info` path carries a column too |
| `test_maps_script_url_shapes_stay_info` / `test_real_firebase_and_maps_wiring_stays_info` / `test_screaming_snake_maps_key_with_real_maps_wiring_stays_info` | the traded-against direction: the narrowing must not re-create the unfixable CI finding |
| `test_client_side_secret_literal_fires_pinecone_key` / `_fires_replicate_key` / `_fires_groq_key` / `_fires_langsmith_key` / `_fires_supabase_pat` | each of the 5 trufflehog-cross-check providers fires, labeled correctly |
| `test_client_side_secret_literal_silent_short_new_provider_prefixes` | FP-bait: each of the 5 new provider prefixes, too short to be real, stays silent |
| `test_client_side_secret_literal_fires_real_slack_token` | a structured `xoxb-<ids>-<secret>` token fires |
| `test_client_side_secret_literal_silent_slack_word_slug` | `xoxp-not-a-real-token-…` word-slug stays silent |
| `test_client_side_secret_literal_multi_provider_one_line` | two distinct-provider keys on one line → two findings |
| `test_client_side_secret_literal_silent_short_prefix` | `sk-loading-…` class + bare `sk-` stay silent |
| `test_client_side_secret_literal_silent_identifier_ending_in_prefix` | `myAKIAHelper` identifier stays silent |
| `test_client_side_secret_literal_silent_in_comment` | a commented example key does not fire |
| `test_client_side_secret_literal_pragma_silences` | the opt-out pragma silences the file |
| `test_client_side_secret_literal_downgrades_nonproduct_not_drops` | a `tests/*.spec.ts` fixture key downgrades to `medium`, is not dropped |
| `test_client_side_secret_literal_nonproduct_pragma_still_fully_suppresses` | the pragma still fully silences a finding even under a test path |
| `test_client_side_secret_literal_applies_gate` | frontend/javascript/typescript on, python/go off |
| `test_issue_1082_ts_backend_key_fires_high` / `test_issue_1082_ts_mcp_positional_anthropic_key_fires_high` | #1082: a TS-only backend's key fires HIGH, including on a non-credential variable name |
| `test_issue_1082_ts_only_firebase_config_stays_info` / `test_issue_1082_ts_only_comment_and_env_read_stay_silent` / `test_issue_1082_ts_only_pragma_silences_but_a_quoted_pragma_does_not` / `test_issue_1082_ts_only_nonproduct_path_is_downgraded_not_dropped` | the traded-against direction of the #1082 widening: the allowlist, comment-stripping, pragma and non-product downgrade all hold on a TS-only repo |
| `test_issue_1082_message_is_side_aware_without_moving_existing_fingerprints` | TS-only gets the side-neutral message; every pre-#1082 profile keeps the original text |
| `test_issue_1082_title_and_remediation_are_side_aware` | TS-only gets a side-neutral title and remediation; every pre-#1082 profile keeps both verbatim |
| `test_issue_1082_ts_only_documented_aws_placeholder_is_an_accepted_high` | the AWS documentation key in a TS-only `.d.ts` fires HIGH (accepted, see "When NOT to flag"), and the pragma silences it |
| `test_issue_1082_checklist_applies_when_matches_the_guard` | the checklist item's `applies_when` agrees with `applies()` |
| `test_issue_1082_real_pipeline_ts_backend_gates_regardless_of_a_stray_js_file` | real detect → select → run: an Express+TS repo gates HIGH at the same locations with or without an `eslint.config.js`; the stray `.js` adds `javascript` and so switches the wording back to the client text, which the test pins |

## Canary — both directions are planted

`canary.py` plants **three** violations for this guard and `EXPECTED_RULES` lists **all three** rules:

| plant | rule | severity |
|---|---|---|
| `components/api_client.js` — an OpenAI `sk-proj-` literal | `hardcoded-api-key-literal` | HIGH |
| `components/firebase_config.js` — a Firebase web `apiKey` with `authDomain`/`projectId` siblings in the same object literal | `public-browser-key` | `info` |
| `components/gcp_server_key.js` — an `AIza…` server key beside a real Firebase config | `google-key-not-public` | HIGH |

Both regressions this guard has shipped were a **silent flip between downgrading and not**, which a
one-rule canary cannot see. Two rules were not enough either, and the reason is worth recording because
it is not obvious: `canary.compare()` asks whether each expected rule fires **anywhere**, so the
non-Google `sk-proj-` plant kept `hardcoded-api-key-literal` alive no matter how far the `AIza`
allowlist widened. A third plant alone did not fix that — **measured, 2026-08-04: adding
`gcp_server_key.js` while every high finding still shared one rule id left the widening undetected.**
What closes it is the *distinct rule id*: only `AIza` tokens can produce `google-key-not-public`, so
widening the allowlist stops it firing and `doctor --canary` reports DEAD.

Verified by mutation. **Every row patches the NAMED constant it claims to change** — the first
version of this table patched the whole `_is_public_browser_key` function while labelling the row a
regex change, and so recorded a result the stated mutation does not produce (#488 fixup gate, C2):

| mutation | canary |
|---|---|
| scope unit reverts to a ±6-line window (H2's class) | **DEAD** |
| the walks stop skipping string content (C1's class) | **DEAD** |
| `_FIREBASE_SIBLING` widened to match anything | **DEAD** |
| allowlist spares every `AIza` (max widening) | **DEAD** — `google-key-not-public` gone |
| allowlist spares nothing (max narrowing) | **DEAD** — `public-browser-key` gone |
| `_MAPS_URL_KEY` widened to any `?key=` URL (H1's own class) | **ALIVE — accepted gap** |

**The accepted gap is real and recorded rather than papered over.** A token inside a `?key=` URL never
reaches the allowlist's generic path, so the single high plant cannot see `_MAPS_URL_KEY` widening.
Covering it would need a second rule id for the URL path; judged not worth the reporting-model churn.
`test_canary_gap_maps_url_widening_is_not_covered` pins the gap and fails if someone closes it without
updating this section.

The siblings in `firebase_config.js` are load-bearing (they are the corroboration; a nearby line would
not be), and in `gcp_server_key.js` the server key must stay **outside** the config object — that is
exactly the H2/F4 shape.

## Known bypasses

A non-listed / internal token shape is not matched (use `gitleaks` for entropy coverage). Splitting the
literal (`"sk-proj-" + rest`) or base64/hex-encoding it evades a prefix match. A key read from a fetched
config at runtime is not a source literal. Minified/bundled JS under `dist/` is not scanned.

## What this guard does NOT prove

Silence does not mean the client holds no secrets — only that no *listed-provider* literal appears in
scanned source. It performs no entropy analysis (a random-looking custom token is invisible), does not
resolve concatenated/encoded values, and says nothing about a secret injected at build time or served in
a runtime config. Pair with `gitleaks` (entropy + git history) and `vite-client-secret` (`.env`) for
fuller coverage.

# Citations

[1] agentsec checklist item `6a-no-provider-key-literal-in-client-js` (§6a)
[2] OWASP:A02
