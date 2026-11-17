"""Guard: a secret baked into a build — client bundle or image layer (§1 / §6a).

The consolidation of two earlier guards (lands #122 ↔ #128, absorbs
`docker-build-arg-secret`). A secret-shaped value threaded into a build leaks two ways:
- a Vite build inlines every `import.meta.env.VITE_*` value into the served JS as a
  string literal (browser exposure), and
- a Dockerfile `ARG`/`ENV` bakes its value into the image layer (`docker history` /
  CI logs) — for ANY image, frontend or backend.

It does NOT scan `.env*` — that vector is owned by the complementary `vite-client-secret`
guard. Here we scan Dockerfiles + frontend source (`import.meta.env`).

Rules:
  1. `build-secret/secret-env-ref` (CRITICAL) — `import.meta.env.VITE_*<secret>` read in
     frontend source. Guaranteed-inlined and actively used.
  2. `build-secret/client-prefixed-secret` — a client-inlined-prefix
     (`VITE_`/`NEXT_PUBLIC_`/`REACT_APP_`/`GATSBY_`) secret-shaped `ARG`/`ENV` in a Dockerfile.
     Severity is calibrated on two axes: (a) is the same name read via `import.meta.env`
     (Vite then inlines it) → CRITICAL; (b) else final image stage → HIGH (published
     image-layer leak), or a discarded non-final stage → MEDIUM.
  3. `build-secret/secret-build-arg` (HIGH/MEDIUM by stage) — a bare (un-prefixed)
     secret-shaped `ARG`/`ENV` in ANY Dockerfile that builds (frontend or backend image),
     with an ENV-value heuristic that skips obviously-benign literals, plus a value gate on the
     ambiguous full-word names (`*_CREDENTIALS`/`*_AUTHORIZATION`/`*_AUTHENTICATION`) that keeps
     config descriptors like `GOOGLE_APPLICATION_CREDENTIALS=/secrets/key.json` silent. That gate is
     itself gated by the name, which is read first: on a name that says the variable HOLDS material
     (`*_KEY`, `*_HASH`, `*_SEED`, ...) only a pointer or a boolean is benign, so no descriptor word,
     env word or short number can silence it on `ARG` (`_is_embedded_secret_value`). `ENV`'s separate
     benign-value gate runs earlier and is name-blind, so `ENV AUTHENTICATION_KEY=test` is still
     silent (see Known bypasses in the design doc).

Secret-token breadth (the Dean+Marconi decision):
- Client-prefixed path stays FP-conservative — `SECRET|PASSWORD|PASSWD|PRIVATE`, NOT bare
  `KEY`/`TOKEN`, because public client vars legitimately ship (`VITE_API_KEY`, a Maps key,
  `VITE_SUPABASE_ANON_KEY`).
- Bare/backend path is broader and includes `TOKEN`: a bare `*_TOKEN` in a Dockerfile is
  almost always a credential (`GITHUB_TOKEN`, `ACCESS_TOKEN`, `DEPLOY_TOKEN`) — there is no
  "public bare `*_TOKEN`" idiom. Bare `KEY` is deliberately left out (noisy: `BUILD_KEY`,
  `CACHE_KEY`); the key-shaped secrets are already caught by the compound forms
  `SECRET_KEY`/`PRIVATE_KEY`.

A public-name allowlist (`PUBLISHABLE`/`PUBLIC`/`ANON`) keeps the flagship's
`VITE_SUPABASE_ANON_KEY` a clean true-negative. Suppress an intentional case with the
inline pragma as a comment: `// security: allow-build-secret` in source, `# …` in a Dockerfile.

Standards: OWASP:A05 (security misconfig) + OWASP:A02 (cryptographic/secret exposure).
"""
from __future__ import annotations

import re
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding, Severity

from .base import CanaryPlant, Guard, iter_dockerfiles, iter_files, pragma_line_set, read, rel

_CODE_SUFFIXES = (".ts", ".tsx", ".js", ".jsx")
_CLIENT_PREFIX = r"(?:VITE_|NEXT_PUBLIC_|REACT_APP_|GATSBY_)"

# Client-prefixed path: FP-conservative — bare KEY/TOKEN excluded so a public
# VITE_API_KEY / VITE_SUPABASE_ANON_KEY does not false-positive.
_CLIENT_SECRET_TOKEN = r"(?:SECRET|PASSWORD|PASSWD|PRIVATE)"  # nosec B105
# Bare/backend path: broader — there is no "public bare *_TOKEN" idiom in a Dockerfile
# build-arg, so TOKEN is included. Bare KEY stays out (noisy); SECRET_KEY/PRIVATE_KEY cover
# the key-shaped secrets via the compound forms.
# HARD tokens: the name alone is enough. A bare `*_TOKEN`/`*_PASSWORD`/`*_SECRET` build arg is a
# credential whatever its default looks like (`ARG DB_PASSWORD=0` is a placeholder for the real
# one, injected via `--build-arg`), so no value check applies.
_HARD_SECRET_TOKEN = (
    r"(?:CLIENT_SECRET|SECRET_KEY|PRIVATE_KEY|API_SECRET"
    r"|PASSWORD|PASSWD|SECRET|PRIVATE|CRED|AUTH|TOKEN)"
)  # nosec B105
# AMBIGUOUS tokens: the full words. They are needed because `CRED`/`AUTH` are PREFIXES of them, so
# the whole-segment boundary below (which exists to keep `AUTHOR`/`TIKTOKEN_CACHE_DIR` silent) also
# rejected `ARG AWS_CREDENTIALS` and `ARG AUTHORIZATION=Bearer sk-live-abc` (#447 review). But the
# full words name a CONFIG DESCRIPTOR at least as often as a credential —
# `GOOGLE_APPLICATION_CREDENTIALS=/secrets/gcp-key.json` is the RECOMMENDED practice (a pointer to
# a file, no secret embedded), `AUTHENTICATION_METHOD=oauth2`, `AUTHENTICATION_PROVIDER=google`.
# The name cannot separate those, so for ambiguous-only names the VALUE decides (see
# `_is_embedded_secret_value`). `AUTHOR`/`AUTHORS` still match nothing — neither the short form
# (boundary) nor the long one (different word).
_AMBIGUOUS_SECRET_TOKEN = r"(?:CREDENTIALS?|AUTHORIZATION|AUTHENTICATION)"  # nosec B105 (detection pattern, not a credential)
_BARE_SECRET_TOKEN = r"(?:" + _AMBIGUOUS_SECRET_TOKEN + r"|" + _HARD_SECRET_TOKEN + r")"  # nosec B105

# Names that are legitimately public even though they look secretish.
_ALLOW_NAME = re.compile(r"PUBLISHABLE|PUBLIC|ANON", re.I)
_PRAGMA = "security: allow-build-secret"

_DOCKER_ARG_ENV = re.compile(r"^\s*(?P<kind>ARG|ENV)\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*(?P<rest>.*)$", re.I)
# A stage boundary. The LAST `FROM` starts the final stage (the default build target);
# a secret declared in an earlier stage is discarded before the published image.
_DOCKER_FROM = re.compile(r"^\s*FROM\s", re.I)
_CLIENT_SECRET_NAME = re.compile(_CLIENT_PREFIX + r"\w*" + _CLIENT_SECRET_TOKEN, re.I)
# Bare token must be a whole `_`-delimited SEGMENT: left-boundaried (string start or `_`) AND
# right-boundaried (not followed by a letter, optional plural `s`). So a non-secret name that
# merely CONTAINS a token — TIKTOKEN_CACHE_DIR (TOKEN inside "TIKTOKEN"), AUTHOR (AUTH...),
# TOKENIZERS_PARALLELISM (TOKEN...) — stays silent, while GITHUB_TOKEN / API_SECRET /
# DB_PASSWORD(S) fire (#423).
_BARE_SECRET_NAME = re.compile(r"(?:^|_)" + _BARE_SECRET_TOKEN + r"s?(?![A-Za-z])", re.I)
# Same boundary, hard tokens only — a name matching this needs no value corroboration.
_HARD_SECRET_NAME = re.compile(r"(?:^|_)" + _HARD_SECRET_TOKEN + r"s?(?![A-Za-z])", re.I)
# Evidence the Dockerfile builds a frontend (cosmetic — refines the bare-rule message).
_FRONTEND_BUILD = re.compile(r"(?:vite build|npm run build|yarn build|pnpm(?: run)? build|\bVITE_)", re.I)
# `import.meta.env.VITE_*<secret>*` referenced in source — the value is inlined + used.
_ENV_REF = re.compile(
    r"import\.meta\.env\.(?P<name>" + _CLIENT_PREFIX + r"\w*" + _CLIENT_SECRET_TOKEN + r"\w*)", re.I
)
# A POINTER to where material lives, not the material: a URL, or an absolute filesystem path
# (`/app/.tiktoken_cache`, `/run/secrets/k.pem`). The URL arm requires the authority to carry NO
# `user:pass@` userinfo — a URL with credentials in it IS the secret, and calling it benign silenced
# `ENV DB_PASSWORD=https://user:pass@host/x` outright, before the hard-token name ever got a say
# (#447 re-review). Written once here: both value patterns below are built from it.
_POINTER = r"https?://(?![^/\s]*@)\S+|/\S+"
# Obviously-benign ENV literal values — skip these. Flag empty/placeholder OR an opaque
# value; skip clear config (numbers, booleans, common env names, pointers).
_BENIGN_ENV_VALUE = re.compile(
    r"^(?:true|false|\d+|production|development|dev|test|staging|local|info|debug|warn|error|"
    + _POINTER + r")$",
    re.I,
)

# --- the ambiguous-name value gate ------------------------------------------------------------
# INVARIANT: a value silences an ambiguous-name finding only when it is POSITIVELY RECOGNISED as
# something other than key material. "Not obviously suspicious" is not a recognition: the previous
# rule (any short single-case alnum word is a descriptor) is the exact shape of most short real
# secrets, so it called `AUTHENTICATION_KEY=hunter2`, `AUTHENTICATION=hunter2` and
# `CREDENTIALS=abc123def` benign (#447 re-review).
#
# PRECEDENCE: the NAME's reading is decided first, and it decides which recognitions the value may
# answer (`_is_embedded_secret_value`). Only an empty value and a `_CRED_MARKER` come before it, and
# both say "material" whatever the name. There are three readings:
# - MATERIAL (`_MATERIAL_NAME`: the name HOLDS it) — only a pointer or a boolean is recognised.
# - SELECTOR (`_DESCRIPTOR_NAME`: the name PICKS a mechanism) — the shared benign shapes (a short
#   number, a boolean, an env word, a pointer, a relative path), then a descriptor by vocabulary
#   identity, by version, or by a digit-free word shape (`_is_descriptor`).
# - BARE (neither) — the shared benign shapes, then a descriptor by vocabulary identity only.
# Anything else is treated as embedded material. The name used to be consulted only by the LAST
# recogniser, so the ones ahead of it answered blind: a short-number knob and an env word silenced
# `ARG AUTHENTICATION_PIN=1234` and `ARG AUTHENTICATION_KEY=test` (#509, absorbing #514).
#
# Shape: letters/`.`/`-`/`_` only. It bounds the open-ended selector arm, where no list can be
# complete (`task-based`, `risk-based`, an unlisted IdP). It admits NO digit. It used to allow two
# trailing ones so `oauth2`/`saml2` would pass, but `<word><1-2 digits>` is also the commonest weak
# password, so `CREDENTIALS_TYPE=hunter2` and `AUTHORIZATION_MODE=letmein1` read as mechanism names
# (#509). A value with a digit is recognised by IDENTITY (the vocabulary, a version) and never by shape.
_DESCRIPTOR_SHAPE = re.compile(r"^[A-Za-z][A-Za-z._-]{0,15}$")
# A version (`v2`, `1.2`, `3.0.1`, `2024.1`, `v2024`): the one digit-bearing value a selector holds
# that no vocabulary could enumerate. Selector arm only — on a bare name a version answers no
# question the name asks. Three arms: an undotted `v` takes at most TWO digits (`v1234` is a PIN
# with a letter in front, #960 review) or a four-digit calendar year `v19xx`/`v20xx` (round-4
# review: `v2024` is a version, `v1234` is not); a dotted form takes up to four digits per
# component. A bare digit run never gets here (the knob recogniser ahead of this one owns it).
# Disclosed cost: an undotted three-digit build number (`v100`) on a selector name fires.
_VERSION_VALUE = re.compile(r"^(?:v\d{1,2}|v(?:19|20)\d{2}|v?\d{1,4}(?:\.\d{1,4}){1,3})$", re.I)
# Mechanism/scheme words — a closed vocabulary.
#
# It originally carried no vendor names, on the reasoning that a vendor value like `google` would
# ride on the descriptor NAME rule instead. That holds only when the name HAS a descriptor suffix.
# On a BARE ambiguous name it does not, and the #447 gate measured the consequence: `ARG
# AUTHENTICATION=keycloak`, `ARG AUTHENTICATION=azure-ad` and `ARG CREDENTIALS=cognito` all went
# 0 -> 1 — identity providers, and the guard's own canonical "benign descriptor" examples, firing
# as if they were embedded key material. That is the unfixable-CI-finding class this whole
# benign-value pass exists to prevent.
#
# So the identity-provider vendors are enumerated here too. Deliberately a CLOSED list and not a
# shape rule: `keycloak` and `swordfish` are both single lowercase words, so nothing lexical
# separates a vendor from a password. Enumerating keeps `AUTHORIZATION=swordfish` material (it is
# in no list) while removing the false positives, where a shape rule would have silenced both.
# The list is only ever consulted where the NAME leaves a selector reading open (`_is_descriptor`),
# so a brand word cannot silence `AUTHENTICATION_KEY=apple`. It is a closed list and therefore
# incomplete by construction — an unlisted IdP (`ory`, `forgerock`, ...) still fires (#447 gate L1);
# the entries added last are the ones whose SIBLINGS were already listed (`pingid`/`pingfederate`
# without `pingone`, `entra` without `entra-id`, `azure-ad`/`azuread` without `azure_ad`).
_VENDOR_VOCAB = frozenset({
    "auth0", "okta", "keycloak", "cognito", "firebase", "entra", "entra-id", "adfs", "onelogin",
    "duo", "azure-ad", "azuread", "azure_ad", "pingid", "pingone", "pingfederate", "gluu",
    "authentik", "fusionauth", "zitadel",
    "google", "github", "gitlab", "bitbucket", "facebook", "twitter", "linkedin", "apple",
    "microsoft", "amazon", "aws", "gcp", "azure", "supabase", "clerk", "workos", "stytch",
})
_DESCRIPTOR_VOCAB = _VENDOR_VOCAB | frozenset({
    "none", "off", "on", "disabled", "enabled", "required", "optional", "default", "custom",
    "auto", "manual", "anonymous", "anon", "basic", "digest", "bearer", "token", "jwt", "jwks",
    "oauth", "oauth1", "oauth2", "oidc", "openid", "saml", "saml2", "ldap", "ldaps", "kerberos",
    "ntlm", "mtls", "tls", "ssl", "sso", "apikey", "api-key", "api_key", "password",  # nosec B105
    "passwordless", "cert", "certificate", "x509", "hmac", "scram", "plain", "session", "cookie",
    "header", "iam", "rbac", "local", "file", "env", "memory", "database", "db",
    # Digit-bearing mechanism words (#509). The selector arm's shape no longer admits a digit, so a
    # mechanism spelled with one is recognised here or not at all. Before, that arm never consulted
    # this list, so `x509`, listed above all along, FIRED on every selector name because the shape
    # rejected its three trailing digits. Kept to algorithm/protocol identifiers: auth methods
    # (pg_hba, MongoDB, Kafka SASL), hash and JWT algorithms, key-store formats, credential sources.
    # None is plausible key material. Precautionary rather than corpus-derived (a digit-bearing value
    # on an ambiguous selector name is rare in the wild), so an unlisted one (`ldap3`, `tls13`) fires.
    # That is the loud, pragma-able direction for a closed list to fail in; extend it word by word.
    # The list is shared, so these also silence a BARE name (`ARG AUTHENTICATION=sha256`, which fired
    # before #509): the same identity reading, and none of them is a secret there either. A MATERIAL
    # name never reaches this list, so `CREDENTIALS_DIGEST=sha256` and `AUTHENTICATION_KEYSTORE=pkcs12`
    # still fire (as they did before #509); the selector form (`*_DIGEST_TYPE`, `*_KEYSTORE_TYPE`) is
    # the one that reads as config. `_ALGORITHM` is not a selector suffix, so `*_DIGEST_ALGORITHM` is
    # a BARE name: a listed value passes there (`=sha256`) and an unlisted one fires (`=bcrypt`).
    "ntlmv2", "md5", "sha1", "sha256", "sha512", "scram-sha-1", "scram-sha-256", "scram-sha-512",
    "krb5", "pkcs11", "pkcs12", "hs256", "rs256", "es256", "ed25519", "s3", "ec2", "k8s", "http2",
})
# The name's last segment names a knob that SELECTS a mechanism — it does not hold one.
_DESCRIPTOR_NAME = re.compile(
    r"_(?:METHOD|MODE|TYPE|KIND|SCHEME|PROVIDER|STRATEGY|BACKEND|FLOW|SOURCE|DRIVER|FORMAT"
    r"|ENABLED|DISABLED|REQUIRED|VERSION)$",
    re.I,
)
# The mirror image: a name whose LAST segment says the variable HOLDS key material. The whole
# descriptor vocabulary — mechanisms and vendors alike — is a SELECTOR vocabulary ("which
# scheme/provider is in use"), so it recognises a value only where that reading is available on the
# name. On a name that ends in `KEY`, it is not: `AUTHENTICATION_KEY=apple` is a weak key, not a
# brand, and `AUTHENTICATION_KEY=password` is a weak key, not a scheme (#447 gate, M1 — the first
# class was opened by the vendor list, the second was open for as long as the vocabulary has existed).
#
# POSITION IS THE RULE, and `$` is what encodes it. The material word has to be the name's HEAD NOUN
# ("the key *for* authentication"), which is the reading that leaves no selector question for a value
# to answer. Matching the segment anywhere also caught it as a QUALIFIER ("credentials *for* the key
# vault", "authentication *by* SSH key", "which *hash* algorithm") — names that do have a selector
# reading, and that fired a CI-blocking HIGH on ordinary config: `SSH_KEY_AUTHENTICATION=enabled`,
# `KEY_VAULT_CREDENTIALS=azure`, `CREDENTIALS_HASH_ALGORITHM=scram` (#447 re-gate, M3). The trailing
# `\d*` keeps `AUTHENTICATION_KEY64` on the material side; `$` is what holds `KEYVAULT`/`KEYCLOAK`/
# `PINNING` out, so it also carries the boundary the old `(?![A-Za-z])` lookahead was there for.
#
# The head nouns are a CLOSED list, so a material word missing from it gets no bound at all. It was
# six words, and `AUTHENTICATION_SEED`/`CREDENTIALS_PHRASE`/`AUTHENTICATION_KEYSTORE` were silenced by
# the whole vocabulary (#509, absorbing #514). It now covers every word that names a secret or a
# container of one. `PRIVKEY`/`SECRETKEY` carry no `_`, so the hard `PRIVATE`/`SECRET_KEY` tokens never
# see them. `PASSCODE` (an MFA / device-pairing code) and `PSK` (a pre-shared key) were still missing
# after #509 and let `ARG AUTHENTICATION_PASSCODE=1234` through (#960 round-6 review). Left out ON
# PURPOSE, because each has a reading that holds no secret: `FINGERPRINT` (a digest of a PUBLIC key or
# cert), `OTP`/`TOTP` (a toggle: `AUTHENTICATION_OTP=enabled`), `RECOVERY` (the same toggle reading:
# `AUTHENTICATION_RECOVERY=enabled`; `RECOVERY_CODE` would need the material word mid-name, the
# disclosed positional residual), bare `MAC` (a MAC address).
#
# TOKEN/SECRET/PASSWORD/CRED/AUTH are deliberately absent: they are HARD tokens, so a name carrying
# one never reaches the value gate at all.
_MATERIAL_NAME = re.compile(
    r"_(?:KEYS?|PIN|HASH|SALT|SIGNATURE|(?:PASS)?PHRASE|SEED|NONCE|DIGEST|HMAC"
    r"|KEYPAIR|KEYRING|KEYSTORE|KEYFILE|PRIVKEY|SECRETKEY|PASSCODE|PSK)\d*$",
    re.I,
)
# What a MATERIAL name still admits: a pointer to the material, or a boolean ("is it on?"). Everything
# `_BENIGN_ENV_VALUE` adds on top of these is a WORD or a NUMBER, and on a name that holds material
# those are just weak material: `ARG AUTHENTICATION_KEY=test`, `ARG AUTHENTICATION_PIN=1234` (#509).
_POINTER_OR_BOOL_VALUE = re.compile(r"^(?:true|false|" + _POINTER + r")$", re.I)
# A relative path — the sibling of `_BENIGN_ENV_VALUE`'s absolute one, for the recommended
# `CREDENTIALS=config/gcp-key.json` pointer form. It must be EXPLICITLY path-shaped: a `./` prefix
# or a config/key file extension. A bare `a/b` rule would have waved through unpadded base64
# (`aGVsbG8vd29ybGQ`), and the segment chars exclude `:`/`@`/`+`/`=` so a URL with userinfo cannot
# pass as a path either.
_PATHY_VALUE = re.compile(
    r"^(?:\.{1,2}/[\w./-]+"
    r"|[\w.-]+(?:/[\w.-]+)*\.(?:json|ya?ml|pem|key|crt|cer|der|p12|pfx|jks|txt|conf|cfg|ini|toml|env|xml)"
    r")$",
    re.I,
)
# Unmistakable embedded credential material — wins over every benign shape above. Every token
# prefix is `\b`-anchored: bare `sk-` matched inside ordinary words (`task-based`, `risk-based`),
# which turned a config descriptor into a HIGH.
_CRED_MARKER = re.compile(
    r"\bBearer\s|\bBasic\s[A-Za-z0-9+/=]{8,}"
    r"|\bsk-|\bsk_|\bpk_live|\brk_live|\bghp_|\bgho_|\bghs_|\bgithub_pat_|\bxox[abpr]-"
    r"|\bAKIA[0-9A-Z]{8,}"
    r"|-----BEGIN|\bey[A-Za-z0-9_-]{8,}\.",  # PEM block / JWT
    re.I,
)

_STANDARDS = ["OWASP:A05", "OWASP:A02"]


def _value_of(rest: str) -> str:
    """The literal value of an `ARG NAME=v` / `ENV NAME v` remainder, unquoted ("" when absent)."""
    val = rest.strip()
    if val.startswith("="):
        val = val[1:].strip()
    return val.strip().strip('"').strip("'")


def _is_secret_value(rest: str) -> bool:
    """For an ENV line, is the value worth flagging? True if empty/placeholder or an opaque
    literal; False for obviously-benign config (numbers, booleans, URLs, env names)."""
    val = _value_of(rest)
    if not val:
        return True  # empty -> build-arg injection signal
    return not _BENIGN_ENV_VALUE.match(val)


def _is_descriptor(name: str, val: str) -> bool:
    """Is `val` a word that NAMES a mechanism/vendor rather than carrying key material?

    PRECONDITION: `name` is not a material name. `_is_embedded_secret_value` routes those first,
    because on a name that ENDS in a segment saying the variable HOLDS material (`*_KEY`, `*_HASH`,
    `*_SEED`, ...) there is no selector reading and no value is a descriptor:
    `AUTHENTICATION_KEY=apple` and `AUTHENTICATION_KEY=password` are both material. Mid-name the
    same word is a QUALIFIER and the selector reading survives, so `SSH_KEY_AUTHENTICATION=enabled`
    and `KEY_VAULT_CREDENTIALS=azure` do reach this function.

    INVARIANT: the descriptor vocabulary recognises a value by reading the variable as a SELECTOR —
    "which scheme/provider is in use". That reading has to be available on the NAME, so the name
    decides how much the value may prove:

    - the name selects one explicitly (`*_METHOD`, `*_PROVIDER`, ...) — a listed word
      (`x509`, `scram-sha-256`), a version (`v2`, `1.2`), or a DIGIT-FREE word for the unlisted rest
      (`AUTHENTICATION_METHOD=task-based`). A digit-bearing word outside the list is material:
      `CREDENTIALS_TYPE=hunter2` (#509). An all-letter one still passes (`=swordfish`), because
      nothing lexical separates it from an unlisted mechanism — the disclosed residual;
    - a bare ambiguous name (`AUTHENTICATION=`, `CREDENTIALS=`) — the value alone decides, by exact
      membership of the closed vocabulary. `AUTHENTICATION=keycloak` is a descriptor;
      `AUTHORIZATION=swordfish` is the same shape, is in no list, and stays material.
    """
    # Exact membership of a CLOSED vocabulary IS the recognition, on either kind of name, and it is
    # tried FIRST. The shape only bounds the open-ended selector arm, and in front of an identity
    # match it could only subtract: behind it, the listed `x509` fired on every selector name (#509),
    # as it once did on bare names (#447 gate, I1).
    if val.lower() in _DESCRIPTOR_VOCAB:
        return True
    if _DESCRIPTOR_NAME.search(name):
        return bool(_VERSION_VALUE.match(val) or _DESCRIPTOR_SHAPE.match(val))
    return False


def _is_embedded_secret_value(name: str, rest: str) -> bool:
    """Does this value look like EMBEDDED SECRET MATERIAL? Used only for the ambiguous full-word
    names (`*_CREDENTIALS`/`*_AUTHORIZATION`/`*_AUTHENTICATION`), where the name is equally
    consistent with a config descriptor, so the value has to decide (#447 review).

    Secret-shaped by DEFAULT — see the invariant above: the benign shapes are an explicit,
    recognised set, so an unrecognised value is material. Recognised: no value at all (a placeholder
    ARG whose real value arrives via `--build-arg`... which is itself a finding), a credential
    marker (always material), a filesystem path (`GOOGLE_APPLICATION_CREDENTIALS=/secrets/
    gcp-key.json` — the recommended practice, the file is not in the image layer), a userinfo-free
    URL, a number/boolean/env name, or a descriptor word. Which of those may answer is the NAME's
    call (the PRECEDENCE block above): a material name admits only a pointer or a boolean.
    """
    val = _value_of(rest)
    if not val:
        return True  # empty -> build-arg injection signal
    if _CRED_MARKER.search(val):
        return True  # `AUTHORIZATION=Bearer sk-live-abc` — real material, whatever else it looks like
    if _MATERIAL_NAME.search(name):
        # Decided HERE, ahead of the knob and env-word recognisers below: they answer "is this
        # config?", a question a name that holds material never asks. A PIN is a short number and a
        # weak key is often an env word, so `ARG AUTHENTICATION_PIN=1234` and `ARG
        # AUTHENTICATION_KEY=test` were silenced before the name was read (#509, absorbing #514).
        return not (_POINTER_OR_BOOL_VALUE.match(val) or _PATHY_VALUE.match(val))
    if val.isdigit():
        # A number is a knob (a port, a flag, a timeout) — but a long digit RUN under a credential
        # name is material, not a knob (`ARG CREDENTIALS=1234567890123456`).
        return len(val) > 6
    if _BENIGN_ENV_VALUE.match(val) or _PATHY_VALUE.match(val):
        return False  # a path / URL / number / boolean / env name
    return not _is_descriptor(name, val)


class BuildSecretGuard(Guard):
    id = "build-secret"
    title = "Secret baked into a build (client bundle or image layer)"
    area = "Build pipeline"

    # frontend/src/build-config.ts: import.meta.env.VITE_API_SECRET read at build time ->
    # fires build-secret/secret-env-ref. The other two expected rules fire from files that stay
    # in the canary base: service.dockerfile (ARG DATABASE_SECRET / ARG API_SECRET_KEY) ->
    # secret-build-arg, and frontend/Dockerfile (ARG VITE_SUPABASE_ANON_KEY) ->
    # client-prefixed-secret.
    canary_plant = CanaryPlant(
        files={
            "frontend/src/build-config.ts": (
                "export const k = import.meta.env.VITE_API_SECRET;  // build-time secret inlined into the bundle\n"
            ),
        },
        expects=frozenset({
            "build-secret/secret-build-arg",
            "build-secret/client-prefixed-secret",
            "build-secret/secret-env-ref",
        }),
    )

    def applies(self, profile: StackProfile) -> bool:
        return bool({"frontend", "docker"} & profile.features)

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        referenced = self._referenced_secret_env_names(root, profile)
        return self._dockerfiles(root, referenced) + self._source_refs(root, profile)

    def _finding(self, sev: Severity, loc: str, msg: str, fix: str, rule: str) -> Finding:
        return Finding(
            check_id=self.id, severity=sev, title=self.title, location=loc,
            message=msg, remediation=fix, rule=rule, standards=list(_STANDARDS),
        )

    def _referenced_secret_env_names(self, root: Path, profile: StackProfile) -> set[str]:
        """Secret-shaped env names actually READ via `import.meta.env` in frontend source —
        a Dockerfile-declared one in this set is guaranteed bundle-inlined (escalate to critical)."""
        fe = root / profile.frontend_dir if profile.frontend_dir else root
        names: set[str] = set()
        for f in iter_files(fe, _CODE_SUFFIXES):
            text = read(f)
            pragma_lines = pragma_line_set(_PRAGMA, text, dialect="js")  # lines whose COMMENT carries it (#424)
            for i, line in enumerate(text.splitlines(), start=1):
                if i in pragma_lines:
                    continue
                for m in _ENV_REF.finditer(line):
                    if not _ALLOW_NAME.search(m.group("name")):
                        names.add(m.group("name"))
        return names

    def _dockerfiles(self, root: Path, referenced: set[str]) -> list[Finding]:
        out: list[Finding] = []
        for f in iter_dockerfiles(root):
            text = read(f)
            lines = text.splitlines()
            pragma_lines = pragma_line_set(_PRAGMA, text, dialect="hash")  # lines whose COMMENT carries it (#424)
            frontend_build = bool(_FRONTEND_BUILD.search(text))
            # The final stage starts at the LAST `FROM` (the default build target); a secret
            # declared before it lives in a stage discarded before the published image.
            from_lines = [n for n, ln in enumerate(lines, start=1) if _DOCKER_FROM.match(ln)]
            last_from = from_lines[-1] if from_lines else 0
            for i, line in enumerate(lines, start=1):
                if i in pragma_lines:
                    continue
                m = _DOCKER_ARG_ENV.match(line)
                if not m:
                    continue
                name, kind, rest = m.group("name"), m.group("kind").upper(), m.group("rest")
                if _ALLOW_NAME.search(name):
                    continue
                # ENV value heuristic: skip ENV lines whose value is obviously benign (a
                # number/bool/URL/path). NOT applied to ARG: an ARG's build-time default is a
                # placeholder — the real secret arrives via `--build-arg`, so a benign-looking
                # default (`ARG DB_PASSWORD=0`) must still fire; the #423 ARG false positives
                # (AUTHOR, TOKENIZERS_PARALLELISM) are handled by the _BARE_SECRET_NAME boundary,
                # not by a value check (PR #447 review).
                if kind == "ENV" and not _is_secret_value(rest):
                    continue
                in_final = i > last_from
                discarded = (
                    " It sits in a non-final build stage discarded before the published image, so the "
                    "residual leak is CI build logs / the build cache (or a direct `--target` build)."
                )
                loc = f"{rel(root, f)}:{i}"
                if _CLIENT_SECRET_NAME.search(name):  # client-inlined prefix
                    if name in referenced:
                        out.append(self._finding(
                            "critical", loc,
                            f"`{name}` is a client-inlined env var carrying a secret, and client code reads it "
                            "via `import.meta.env`, so Vite inlines it into the served bundle — browser exposure.",
                            "Keep secrets server-side (no client prefix); the client needs only the publishable "
                            f"key. Rotate if it ever built. Suppress an intentional case with `# {_PRAGMA}`.",
                            "build-secret/client-prefixed-secret",
                        ))
                    elif in_final:
                        out.append(self._finding(
                            "high", loc,
                            f"`{name}` is a client-prefixed secret baked into the published image layer (visible via "
                            "`docker history` / CI logs); it would bundle-inline the moment any code reads it.",
                            f"Keep secrets server-side. Rotate if it built. Suppress with `# {_PRAGMA}`.",
                            "build-secret/client-prefixed-secret",
                        ))
                    else:
                        out.append(self._finding(
                            "medium", loc,
                            f"`{name}` is a client-prefixed secret, not bundle-inlined." + discarded,
                            f"Keep secrets server-side. Suppress with `# {_PRAGMA}`.",
                            "build-secret/client-prefixed-secret",
                        ))
                    continue
                if _BARE_SECRET_NAME.search(name):  # bare secret in ANY image (backend coverage)
                    # A name whose ONLY secret evidence is an ambiguous full word needs the value to
                    # corroborate: `AUTHENTICATION_METHOD=oauth2` and the recommended
                    # `GOOGLE_APPLICATION_CREDENTIALS=/secrets/gcp-key.json` embed nothing, while
                    # `AWS_CREDENTIALS` (no value) and `AUTHORIZATION=Bearer sk-live-abc` do (#447
                    # review). A hard token needs no value corroboration HERE — but note an ENV line
                    # has already passed the benign-value gate above, so `ENV DB_PASSWORD=<a path or
                    # a number>` is skipped before this point; only ARG fires on the name alone
                    # (#447 re-review corrected the claim that it was "ARG and ENV alike").
                    if not _HARD_SECRET_NAME.search(name) and not _is_embedded_secret_value(name, rest):
                        continue
                    sev: Severity = "high" if in_final else "medium"
                    scope = "a frontend build" if frontend_build else "an image"
                    chan = (
                        f"bakes into the published image layer of {scope} (visible via `docker history` / CI logs)."
                        if in_final else f"is declared in {scope}." + discarded
                    )
                    out.append(self._finding(
                        sev, loc,
                        f"`{name}` is a secret-shaped build arg/env — it {chan}",
                        "Don't pass secrets as build args; inject at runtime or use BuildKit "
                        f"`--mount=type=secret`. Rotate if it built. Suppress with `# {_PRAGMA}`.",
                        "build-secret/secret-build-arg",
                    ))
        return out

    def _source_refs(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []
        fe = root / profile.frontend_dir if profile.frontend_dir else root
        for f in iter_files(fe, _CODE_SUFFIXES):
            text = read(f)
            pragma_lines = pragma_line_set(_PRAGMA, text, dialect="js")
            for i, line in enumerate(text.splitlines(), start=1):
                if i in pragma_lines:
                    continue
                for m in _ENV_REF.finditer(line):
                    name = m.group("name")
                    if _ALLOW_NAME.search(name):
                        continue
                    out.append(self._finding(
                        "critical", f"{rel(root, f)}:{i}",
                        f"`import.meta.env.{name}` reads a secret-shaped client env var — Vite inlines it into the "
                        "served JS as a string literal, so anyone who views the bundle reads the secret.",
                        "Move the secret behind a backend endpoint; the client reads only publishable values. "
                        f"Rotate (assume it shipped). Suppress with `// {_PRAGMA}`.",
                        "build-secret/secret-env-ref",
                    ))
        return out
