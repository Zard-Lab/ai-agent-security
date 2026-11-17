---
type: Guard
title: "build-secret"
description: "Secret baked into a build (client bundle or image layer)."
timestamp: "2026-09-27T17:16:51Z"
guard_id: "build-secret"
checklist_section: ["1"]
standards: ["OWASP:A02", "OWASP:A05", "OWASP:CheatSheet"]
---

# Secret baked into a build (client bundle or image layer)

_Added 2026-06-22 — the consolidation of `frontend-secret-in-build` (#122, Dean) and
`docker-build-arg-secret` (#127, Marconi), landed per the #128 prototype + the Dean+Marconi
token decision. Absorbs `docker-build-arg-secret`; the `.env*` vector stays with the
complementary `vite-client-secret` guard._

---

## The threat

A secret-shaped value threaded into a build leaks two ways. A Vite build **inlines every
`import.meta.env.VITE_*` value into the served JS** as a string literal — anyone who views the bundle reads it. A
Dockerfile **`ARG`/`ENV` bakes its value into the image layer** (`docker history` / `docker inspect`, and CI build
logs) — for **any** image, frontend or backend. Who: a visitor reading the public bundle, or anyone with
registry/CI-log access. Effect: account-takeover-grade credential exposure (a Stripe `sk_…`, an OAuth client
secret, a `GITHUB_TOKEN`, a DB password). Severity **critical** for an actively-read `import.meta.env.VITE_*SECRET*`;
**high** for a secret in the published image stage; **medium** for one in a discarded build stage. Standards
`["OWASP:A05", "OWASP:A02"]`.

This guard owns the **build + source** surface. It deliberately does **NOT** scan `.env*` — that is
`vite-client-secret`'s job; together they cover §6a (the env-file half + the `import.meta.env` half).

## Why it's often introduced / Why this guard fits the stack

Developers prefix env vars with `VITE_`/`NEXT_PUBLIC_` so the client can read them — not realizing the prefix means
"inline into the public bundle" — and pass everything (including server secrets) as Docker build args because
that's the path of least resistance in CI:

```dockerfile
ARG VITE_STRIPE_SECRET_KEY            # → browser bundle (if read) + image layer
ENV VITE_STRIPE_SECRET_KEY=$VITE_STRIPE_SECRET_KEY
ARG GITHUB_TOKEN                      # → image layer (backend image too)
ARG DB_PASSWORD
```

Any Vite/React **or** Docker stack is exposed, so the guard gates on `{frontend, docker}`.

## Detection design

1. **`applies()` gate** — `{"frontend", "docker"} & profile.features`.
2. **Files scanned** — all Dockerfiles via `base.iter_dockerfiles(root)` (`Dockerfile`, `Dockerfile.<x>`, **and
   `*.dockerfile`** — the `service.dockerfile` convention), plus frontend source (`.ts/.tsx/.js/.jsx` under
   `profile.frontend_dir`). It does **NOT** read `.env*` (→ `vite-client-secret`).
3. **Secret-name model (the Dean+Marconi decision)** — two token sets:
   - **Client-prefixed path** (FP-conservative): `SECRET|PASSWORD|PASSWD|PRIVATE`, deliberately **not** bare
     `KEY`/`TOKEN` — a public `VITE_API_KEY` / Maps key / `VITE_SUPABASE_ANON_KEY` legitimately ships.
   - **Bare/backend path** (broader): adds `CRED|AUTH|**TOKEN**` to the compound forms
     (`CLIENT_SECRET|SECRET_KEY|PRIVATE_KEY|API_SECRET`). A bare `*_TOKEN` in a Dockerfile is almost always a
     credential (`GITHUB_TOKEN`, `ACCESS_TOKEN`, `DEPLOY_TOKEN`); there is no "public bare `*_TOKEN`" idiom. Bare
     `KEY` stays out (noisy: `BUILD_KEY`, `CACHE_KEY`); key-shaped secrets are caught by `SECRET_KEY`/`PRIVATE_KEY`.
     The bare match is **word-boundary anchored** (`(?:^|_)<token>`), so a non-secret name that merely *contains* a
     token mid-word does not false-positive — `TIKTOKEN_CACHE_DIR` ("TOKEN" inside "TIKTOKEN") stays silent while
     `GITHUB_TOKEN` fires. The ENV-value heuristic also treats an **absolute path** value (`/app/...`) as benign
     config. (Both shaken out by the empirical pass over the flagship's backend Dockerfiles.)
   - Allowlist `_ALLOW_NAME = PUBLISHABLE|PUBLIC|ANON` exempts public names even if otherwise matched (keeps the
     flagship's `VITE_SUPABASE_ANON_KEY` a true-negative).
4. **`secret-env-ref`** (CRITICAL) — `import.meta.env.(VITE_*<client-secret>*)` in frontend source. Guaranteed
   inlined and actively used. Rule `build-secret/secret-env-ref`.
5. **`client-prefixed-secret`** — a Dockerfile `ARG`/`ENV` matching the client-prefixed secret name. Checked
   **before** the bare rule. **Severity is calibrated on two axes**: (a) the same name is read via
   `import.meta.env` in source → **CRITICAL** (bundle inlining, carried into the final image via the build output —
   stage-independent); else (b) final/single stage → **HIGH** (published image-layer leak); else discarded
   non-final stage → **MEDIUM** (residual leak = CI logs / build cache / a `--target` build). Rule
   `build-secret/client-prefixed-secret`.
6. **`secret-build-arg`** — a bare secret-shaped `ARG`/`ENV` in **any** Dockerfile (frontend or backend image).
   HIGH in the final/single stage, MEDIUM in a discarded stage. An **ENV-value heuristic** (`_is_secret_value`)
   skips obviously-benign literals (numbers, booleans, URLs, common env names) so `ENV SECRET_VERSION=2` stays
   silent while `ENV API_SECRET=` (empty → build-arg injection) and `ENV DB_PASSWORD=hunter2` (opaque) fire. Rule
   `build-secret/secret-build-arg`.
6b. **The ambiguous-name value gate** (`_is_embedded_secret_value`, added across #447). The bare-path token set
   splits in two. **HARD** tokens (`TOKEN|SECRET|PASSWORD|PASSWD|PRIVATE|CRED|AUTH` + the compound forms) fire on
   the *name alone* — an `ARG DB_PASSWORD=0` is a placeholder for a `--build-arg` injection, so no value can
   excuse it. **AMBIGUOUS** tokens are the full words `CREDENTIALS?|AUTHORIZATION|AUTHENTICATION`, which are
   needed because `CRED`/`AUTH` are only *prefixes* of them and the whole-segment boundary rejected
   `ARG AWS_CREDENTIALS`. Those full words name a config descriptor at least as often as a credential
   (`GOOGLE_APPLICATION_CREDENTIALS=/secrets/gcp-key.json` is the *recommended* practice), so for an
   ambiguous-only name the **value** decides.

   The value gate's invariant: **a value silences the finding only when it is POSITIVELY RECOGNISED as something
   other than key material** — "not obviously suspicious" is not a recognition, because most short real secrets
   look like an ordinary word. An absent value still fires (that IS the build-arg injection signal), and a
   `_CRED_MARKER` (`Bearer `, `sk-`, `ghp_`, `AKIA…`, a PEM header, a JWT) fires whatever the name says.

   **The name is read first, and it decides which recognitions the value may answer** (#509, absorbing #514).
   Before #509 the name was consulted only by the *last* recogniser, so the ones ahead of it answered blind: a
   short-number knob and an env word silenced `ARG AUTHENTICATION_PIN=1234` and `ARG AUTHENTICATION_KEY=test`.
   There are three readings:

   | Name reading | Recognised as not-material (silences) | Stays silent | Fires |
   |---|---|---|---|
   | **material**: the name *holds* it (`_MATERIAL_NAME`) | a pointer (absolute or relative path, userinfo-free URL) or a boolean | `AUTHENTICATION_KEYFILE=/run/secrets/k.pem` | `AUTHENTICATION_KEY=apple`, `=test`, `AUTHENTICATION_PIN=1234` |
   | **selector**: the name *picks* a mechanism (`_DESCRIPTOR_NAME`) | the shared benign shapes, then a listed word, a version, or a **digit-free** word | `AUTHENTICATION_METHOD=x509`, `=task-based`, `AUTHENTICATION_VERSION=1.2` | `CREDENTIALS_TYPE=hunter2` |
   | **bare**: neither | the shared benign shapes, then a listed word only | `AUTHENTICATION=keycloak` | `AUTHORIZATION=swordfish` |

   The *shared benign shapes* are a short number (≤6 digits), a boolean or env word (`_BENIGN_ENV_VALUE`), and a
   pointer (`_BENIGN_ENV_VALUE`'s URL and absolute-path arms, `_PATHY_VALUE`'s relative one). A **descriptor** is a
   value that *names* the mechanism rather than carrying it, which is a **selector** reading ("which
   scheme/provider is in use"). That reading has to be available on the name, which is why the name comes first
   (#447 gate, M1).
   - **Material names.** `_MATERIAL_NAME` is `*_KEY(S)`, `*_PIN`, `*_HASH`, `*_SALT`, `*_SIGNATURE`,
     `*_(PASS)PHRASE`, `*_SEED`, `*_NONCE`, `*_DIGEST`, `*_HMAC`, `*_KEYPAIR`, `*_KEYRING`, `*_KEYSTORE`,
     `*_KEYFILE`, `*_PRIVKEY`, `*_SECRETKEY`, `*_PASSCODE` and `*_PSK` (the last two added by the #960 round-6
     review: `ARG AUTHENTICATION_PASSCODE=1234` and `ARG CREDENTIALS_PSK=123456` fell through to the short-number
     knob), each with an optional trailing digit run. There is no selector
     reading, so no vocabulary word, env word or short number recognises the value: `AUTHENTICATION_KEY=apple` is
     a weak key, not a brand, and `AUTHENTICATION_KEY=password` is a weak key, not a scheme. **Position is the
     rule**: the material word has to be the head noun. Mid-name it is a *qualifier* and the selector reading
     survives — `SSH_KEY_AUTHENTICATION=enabled`, `KEY_VAULT_CREDENTIALS=azure` and
     `CREDENTIALS_HASH_ALGORITHM=scram` are descriptors, and were CI-blocking HIGHs while the match floated
     (#447 re-gate, M3). The cost is disclosed and pinned by FP-bait: `AUTHENTICATION_KEY_ID`,
     `AUTHENTICATION_KEYS_COUNT` and `KEY_AUTHENTICATION` are selector names too.
   - **Selector names.** A listed word is recognised by identity first (`x509`, `scram-sha-256`), then a
     version (`_VERSION_VALUE`: `v2`, `1.2`, `3.0.1`, `2024.1`, `v2024`; an undotted `v` takes at most two
     digits or a four-digit calendar year, so `v1234` is a PIN with a letter in front and fires while `v2024`
     stays a version, #960 review; an undotted three-digit build number such as `v100` fires, disclosed), then a
     **digit-free** word shape (`_DESCRIPTOR_SHAPE`:
     letters, `.`, `-`, `_`, at most 16 characters) for the open-ended rest (`task-based`, an unlisted IdP). A
     digit-bearing word is recognised by identity or not at all, because `<word><1-2 digits>` is the commonest
     weak-password form (#509). The digit-bearing mechanism words are listed for that reason: `ntlmv2`, `md5`,
     `sha1`/`sha256`/`sha512`, `scram-sha-1`/`-256`/`-512`, `krb5`, `pkcs11`/`pkcs12`, `hs256`/`rs256`/`es256`,
     `ed25519`, `s3`, `ec2`, `k8s`, `http2`. The list is precautionary rather than corpus-derived: a real
     digit-bearing value on an ambiguous selector name is rare in the wild.
   - **Bare names** (`AUTHENTICATION=`, `CREDENTIALS=`). The value alone decides, by **exact membership** of the
     closed vocabulary of mechanism words (`oauth2`, `saml`, `mtls`, `x509`, …) and identity-provider vendors
     (`keycloak`, `okta`, `cognito`, `azure-ad`, …). Deliberately a closed enumeration and **not** a shape
     rule: `keycloak` and `swordfish` are both one lowercase word, so nothing lexical separates a vendor from a
     password — enumerating removes the false positives while keeping `AUTHORIZATION=swordfish` material.
     The digit-bearing words the selector arm needs sit in the same list, so a bare name recognises them too:
     `ARG AUTHENTICATION=sha256` and `ARG CREDENTIALS=s3` fired before #509 and are silent now. The match is
     still exact identity, so an unlisted `<word><digits>` (`AUTHENTICATION=admin12`) or a near miss of a
     listed word (`sha257`) still fires.
7. Inline opt-out pragma — a `# security: allow-build-secret` comment in a Dockerfile, `// …` in source —
   skips the line (a string literal quoting the phrase does not count, #424).

   _Stage caveat:_ "final stage = content after the last `FROM`" is the default build target; a `--target <stage>`
   build of an earlier stage would publish it. The MEDIUM tier names this rather than claiming zero risk.

## When NOT to flag

The allowlist is load-bearing: the flagship `frontend/Dockerfile` threads `VITE_SUPABASE_ANON_KEY` (intentionally
public) — exempt by both carrying no client-secret token and by `ANON` in the allowlist. `VITE_STRIPE_PUBLISHABLE_KEY`
is exempt (`PUBLISHABLE`). Bare `BUILD_KEY`/`CACHE_KEY` do **not** fire (bare `KEY` excluded). An ENV with a benign
config value (`ENV NODE_ENV=production`, a URL, a number) is skipped by the value heuristic. The pragma covers a
reviewed, intentional case.

An **ambiguous**-only name is not flagged when its value is recognised as non-material (§Detection design 6b):
`ARG AUTHENTICATION_METHOD=oauth2`, `ARG AUTHENTICATION_METHOD=x509`, `ENV AUTHENTICATION_PROVIDER=google`,
`ARG AUTHENTICATION=keycloak`, `ARG GOOGLE_APPLICATION_CREDENTIALS=/secrets/gcp-key.json`. It **is** flagged
whenever the name says the variable holds material and the value is not a pointer or a boolean
(`ARG AUTHENTICATION_KEY=apple`, `=test`, `ARG AUTHENTICATION_PIN=1234`), whenever a selector name carries a
digit-bearing word that is neither listed nor a version (`ARG CREDENTIALS_TYPE=hunter2`), and whenever the value on
a bare name is unlisted (`ARG AUTHORIZATION=swordfish`). Hard-token names are never subject to this gate at all.

One false positive follows from the material rule and is kept on purpose. An algorithm or format identifier on a
material name is flagged: `ARG CREDENTIALS_DIGEST=sha256`, `ARG AUTHENTICATION_KEYPAIR=ed25519` and
`ARG AUTHENTICATION_KEYSTORE=pkcs12` all fire, as they did before #509. A name that holds material admits only a
pointer or a boolean, because a word there is usually a weak key. Name the knob with a selector suffix instead
(`*_DIGEST_TYPE`, `*_KEYPAIR_TYPE`, `*_KEYSTORE_TYPE`), which reads as config and stays silent for a listed or
digit-free value, or use the pragma. `_ALGORITHM` is **not** a selector suffix: `*_DIGEST_ALGORITHM` is read as
a bare name, so `=sha256` is silent only because `sha256` is listed, and an unlisted `=bcrypt` fires.

## Tests

| Test | What it checks |
|---|---|
| `test_build_secret_source_ref_is_critical` | `import.meta.env.VITE_STRIPE_SECRET_KEY` in src → CRITICAL `secret-env-ref` |
| `test_build_secret_client_prefixed_escalates_when_read_in_src` | Dockerfile `VITE_*SECRET` also read in src → CRITICAL `client-prefixed-secret` |
| `test_build_secret_client_prefixed_final_stage_is_high` | client-prefixed secret in the final/single stage → HIGH |
| `test_build_secret_client_prefixed_discarded_stage_is_medium` | client-prefixed secret in a discarded build stage → MEDIUM |
| `test_build_secret_backend_bare_secret` | backend `ARG DB_PASSWORD` → HIGH `secret-build-arg` (the §1 verifier) |
| `test_build_secret_bare_token_fires` | backend `ARG GITHUB_TOKEN` → HIGH `secret-build-arg` (Marconi: TOKEN in) |
| `test_build_secret_token_substring_no_fp` | `TIKTOKEN_CACHE_DIR` → silent (word-boundary; empirical flagship FP) |
| `test_build_secret_bare_key_silent` | backend `ARG BUILD_KEY` → silent (Marconi: bare KEY out) |
| `test_build_secret_env_value_heuristic` | `ENV SECRET_VERSION=2` skipped; `ENV API_SECRET=` / `ENV DB_PASSWORD=hunter2` fire |
| `test_build_secret_dockerfile_suffix_scanned` | a `*.dockerfile` file is scanned (no regression vs docker-build-arg-secret) |
| `test_build_secret_public_anon_key_is_clean_negative` | `VITE_SUPABASE_ANON_KEY` (client + source) → silent (flagship anchor) |
| `test_build_secret_pragma_opt_out` | `security: allow-build-secret` → silent |
| `test_build_secret_not_applicable_without_frontend_or_docker` | `applies()` False without frontend/docker |
| `test_build_secret_url_with_userinfo_is_not_a_benign_env_value` | a URL carrying `user:pass@` is never a benign pointer: `ENV DB_PASSWORD=https://user:pass@…`, a `postgresql://u:p@…` DSN, and (#509) `ARG AUTHENTICATION_KEY=https://user:pass@…` through the material arm's shared `_POINTER` → fire |
| `test_build_secret_ambiguous_name_with_config_value_stays_silent` | `AUTHENTICATION_METHOD=oauth2`, `GOOGLE_APPLICATION_CREDENTIALS=/…` etc. → silent |
| `test_build_secret_credential_markers_are_word_boundaried` | `sk-` inside `task-based` is not a key; every real marker form still fires |
| `test_build_secret_vendor_value_on_a_bare_ambiguous_name_is_benign` | `ARG AUTHENTICATION=keycloak\|azure-ad\|auth0\|okta`, `CREDENTIALS=cognito` → silent |
| `test_build_secret_material_values_still_fire` | the traded-against direction: an unlisted word (`swordfish`, `keycloack`, and `bcrypt` on the bare-read `CREDENTIALS_DIGEST_ALGORITHM`) and **any** word under a material name (`AUTHENTICATION_KEY=apple\|password`) still fire |
| `test_build_secret_selector_readings_stay_silent` | the material-name gate's own FP-bait: `AUTHENTICATION_KEY_PROVIDER=google`, the `$`-anchor bait (`CREDENTIALS_KEYVAULT`, `AUTHENTICATION_KEYCLOAK`, `CREDENTIALS_PINNING`) and the closed-list siblings (`pingone`, `entra-id`, `azure_ad`, `x509`) → silent |
| `test_build_secret_selector_name_does_not_admit_a_digit_bearing_password` | #509: `CREDENTIALS_TYPE=hunter2`, `AUTHENTICATION_SOURCE=trustno1`, … one per suffix family, on `ARG` and `ENV`, plus the version arm's bait `CREDENTIALS_TYPE=v1234\|v2100` / `AUTHENTICATION_VERSION=v123\|v1899` (#960 review) → fire |
| `test_build_secret_selector_name_admits_a_listed_or_versioned_mechanism` | #509's narrowing: `AUTHENTICATION_METHOD=x509\|scram-sha-256`, `CREDENTIALS_FORMAT=sha256`, `AUTHENTICATION_VERSION=1.2\|v2\|v10\|v1.2.3\|v2024\|v1999`, `CREDENTIALS_FORMAT=2024.1`, the selector form of an algorithm on a material noun (`CREDENTIALS_DIGEST_TYPE=bcrypt`, `AUTHENTICATION_KEYSTORE_TYPE=pkcs12`), and an unlisted digit-free `ory` → silent |
| `test_build_secret_bare_name_admits_a_listed_digit_bearing_mechanism` | the shared list's bare-name reading: `ARG AUTHENTICATION=sha256\|md5\|ntlmv2`, `CREDENTIALS=s3\|k8s`, `AUTHORIZATION=ec2` → silent (all fired before #509) |
| `test_build_secret_bare_name_still_fires_on_an_unlisted_digit_bearing_word` | its traded-against direction: `AUTHENTICATION=hunter2`, `CREDENTIALS=admin12`, and the near misses `sha257`, `s33` → fire |
| `test_build_secret_material_name_is_read_before_any_value_recogniser` | #509/#514: every added material noun on a vocabulary value, and `ARG AUTHENTICATION_KEY=test\|local\|0`, `ARG AUTHENTICATION_PIN=1234` → fire |
| `test_build_secret_material_name_still_admits_a_pointer_or_boolean` | the FP-bait for that widening: a path, a userinfo-free URL or `true` on a material name → silent; `ENV AUTHENTICATION_KEY=local` stays silent by decision |

Liveness: the canary plants `service.dockerfile` (bare secret → `secret-build-arg`), `frontend/Dockerfile`
(`VITE_WIDGET_SECRET` → `client-prefixed-secret`), and `frontend/src/build-config.ts`
(`import.meta.env.VITE_API_SECRET` → `secret-env-ref`); its `VITE_SUPABASE_ANON_KEY` build arg is the silent FP-bait.

## Known bypasses

- **Renamed secret** — a secret env var whose name lacks a recognized token (e.g. `ARG GH_PAT`) evades the name
  model. The token sets are deliberately curated to keep false positives near zero.
- **Indirection** — a value fetched at runtime from a config service, or a split string literal, evades static
  pattern-matching.
- **`.env*` files** — out of scope here (owned by `vite-client-secret`).
- **`--target` builds** — a non-final stage built directly is published; the MEDIUM message notes this.
- **The descriptor vocabulary is a deliberate fail-open** (the largest one here). On a *bare* ambiguous name, a
  value that is one of the listed mechanism/vendor words silences a would-be HIGH — so a real secret that
  happens to *be* one of those words (`ARG AUTHORIZATION=apple`) goes unreported. That is the price of the closed
  enumeration: nothing lexical separates `keycloak` from `swordfish`, and firing on the vendor names produced an
  unfixable CI finding on ordinary IdP configuration. The exposure is bounded by the name — where the name ends
  in a material segment, no vocabulary word can silence it (`_MATERIAL_NAME`).
  **That bound is itself a closed list, so a material word missing from it is not bounded at all.** #447 shipped
  it with six words (`KEY(S)`/`PIN`/`HASH`/`SALT`/`SIGNATURE`/`PASSPHRASE`), and `AUTHENTICATION_SEED`,
  `CREDENTIALS_PHRASE`, `AUTHENTICATION_KEYSTORE` and the rest were silenced by the **whole** vocabulary
  (#447 re-gate, L2; #514). #509 extended it to every word that names a secret or a container of one (§Detection
  design 6b); the #960 round-6 review added `PASSCODE` and `PSK`. Four words stay out **on purpose**, because each
  has a reading that holds no secret: `FINGERPRINT` (a digest of a *public* key or cert), `OTP`/`TOTP` (a toggle:
  `AUTHENTICATION_OTP=enabled`), `RECOVERY` (the same toggle reading, `AUTHENTICATION_RECOVERY=enabled`; a
  `RECOVERY_CODE` puts the material word mid-name, the positional residual below), and bare `MAC` (a MAC address).
  So `CREDENTIALS_FINGERPRINT=apple`, `AUTHENTICATION_OTP=okta` and `AUTHENTICATION_RECOVERY=enabled` stay silent,
  and so does any head noun nobody has listed yet.
- **The bound is POSITIONAL as well as lexical, which is a second and larger residual** (#447 agentic gate, M1).
  `_MATERIAL_NAME` is anchored to the name's last segment, so it protects `AUTHENTICATION_KEY` but **not**
  `AUTHENTICATION_KEY_<anything>`. Stated structurally, because it is exhaustive rather than a sample: for a
  name `<AMBIGUOUS>_<MATERIAL>_<TAIL>`, if `TAIL` is not itself a `_DESCRIPTOR_NAME` suffix (in which case it
  was already exempt) and not a bare digit run (absorbed by the `\d*`), the material bound does not apply and
  the **whole** vocabulary can silence it. Verified by enumeration over 987 such names (3 ambiguous bases × 7
  material words × 47 tails): **987 of 987** are silent on a vocabulary value, with zero counterexamples. So
  `ARG AUTHENTICATION_KEY_VALUE=password`, `AUTHENTICATION_KEY_MATERIAL=password`, `AUTHENTICATION_KEY_PEM=
  password`, `CREDENTIALS_KEY_PRIMARY=password` and `AUTHENTICATION_KEY_V2=password` (key rotation) are all
  silent, while the same names without the tail fire. The same enumeration establishes the bound: **987 of
  987** still fire on a non-vocabulary value (`=hunter2`), so the exposure is confined to the vocabulary
  words and does not reach an arbitrary secret. Anchoring is still correct — matching the material word in
  any position was itself a CI-blocking false-positive class — but the cost is this class, not the three
  named cases the anchoring commit disclosed. (That enumeration predates #509's longer material list; the
  structural statement holds for every word on it.) #509 left this open on purpose: closing it needs a tail
  vocabulary (`ID`/`COUNT` vs `VALUE`/`V2`), which reopens the M3 false-positive class.
- **On `ENV`, a benign-looking value silences even a material name.** `ENV AUTHENTICATION_KEY=local` is silent,
  and so are `=test`, `=dev`, a number, a boolean, a URL or a path. The `ENV` benign-value gate
  (`_is_secret_value`) runs before any name is read, for **every** name, hard tokens included: `ENV
  DB_PASSWORD=test` is silent too. On `ARG` this is closed (#509, absorbing #514). A material name is read
  before the knob and env-word recognisers, so `ARG AUTHENTICATION_KEY=test` and `ARG AUTHENTICATION_PIN=1234`
  fire, just as `ARG DB_PASSWORD=test` always has. The `ENV` gate is left as it is. It is the deliberate price of
  not flagging ordinary config, and changing it would be a precision decision for every name, not for this gate.
- **The selector-suffix list is the mirror-image fail-open, narrowed to all-letter words.** A
  `_DESCRIPTOR_NAME` suffix waves through any **digit-free** word, so `ARG CREDENTIALS_TYPE=swordfish` stays
  silent. Nothing lexical separates it from an unlisted mechanism or vendor word, and a vocabulary-only rule
  would fire on `task-based`, `risk-based` and every unlisted IdP. Until #509 the shape also admitted two
  trailing digits, so `CREDENTIALS_TYPE=hunter2` and `AUTHENTICATION_SOURCE=trustno1` were silent on every
  selector name, while the listed `x509` fired on all of them. A digit-bearing value is now recognised only by
  identity: a listed word or a version. That closed list fails the loud way. An unlisted digit-bearing mechanism
  on a selector name (`ldap3`, `tls13`) fires, and fixing it takes one word added to the list or one pragma.
- **The closed vendor list is incomplete by construction** — an unlisted identity provider (`ory`, `forgerock`,
  `jumpcloud`, `descope`, `authelia`, …) still fires on a bare ambiguous name. Adding one is a one-word change;
  making it a shape rule is not an option (see above).
- **Short numeric values on a non-material name** — the number gate treats a run of ≤6 digits as a knob (a
  port, a flag, a version), so `ARG CREDENTIALS=12345` is silent. Longer digit runs are material. On a material
  name the knob does not apply (#509): `ARG AUTHENTICATION_KEY=12345` and `ARG AUTHENTICATION_PIN=1234` fire.

## What this guard does NOT prove

That a flagged value is a real, live secret (it matches the *name/wiring*, not the value — complements gitleaks,
which matches literal values). It does not prove the absence of secrets in `.env*` (that is `vite-client-secret`)
nor catch runtime exposure (a leaking endpoint, logs, a deploy-time paste).

# Citations

[1] agentsec checklist item `1-no-secret-in-docker-build-arg` (§1)
[2] OWASP:A02
[3] OWASP:A05
[4] OWASP:CheatSheet
