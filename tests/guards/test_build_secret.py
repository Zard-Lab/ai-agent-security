from __future__ import annotations

import pytest

from agentsec.guards.build_secret import BuildSecretGuard
from tests.guards._common import *  # noqa: F401,F403


def test_build_secret_source_ref_is_critical(tmp_path: Path) -> None:
    (tmp_path / "frontend").mkdir()
    (tmp_path / "frontend" / "pay.ts").write_text(
        "const k = import.meta.env.VITE_STRIPE_SECRET_KEY\n", encoding="utf-8"
    )
    rules = _bs_rules(BuildSecretGuard().run(tmp_path, _bs_prof(tmp_path)))
    assert ("build-secret/secret-env-ref", "critical") in rules

def test_build_secret_client_prefixed_escalates_when_read_in_src(tmp_path: Path) -> None:
    (tmp_path / "frontend").mkdir()
    (tmp_path / "frontend" / "pay.ts").write_text(
        "const k = import.meta.env.VITE_STRIPE_SECRET_KEY\n", encoding="utf-8"
    )
    (tmp_path / "Dockerfile").write_text(
        "FROM node\nARG VITE_STRIPE_SECRET_KEY\nRUN vite build\n", encoding="utf-8"
    )
    rules = _bs_rules(BuildSecretGuard().run(tmp_path, _bs_prof(tmp_path)))
    assert ("build-secret/client-prefixed-secret", "critical") in rules

def test_build_secret_client_prefixed_final_stage_is_high(tmp_path: Path) -> None:
    (tmp_path / "Dockerfile").write_text(
        "FROM node\nARG VITE_APP_SECRET\nRUN npm run build\n", encoding="utf-8"
    )
    rules = _bs_rules(BuildSecretGuard().run(tmp_path, _bs_prof(tmp_path)))
    assert ("build-secret/client-prefixed-secret", "high") in rules

def test_build_secret_client_prefixed_discarded_stage_is_medium(tmp_path: Path) -> None:
    (tmp_path / "Dockerfile").write_text(
        "FROM node AS build\nARG VITE_APP_SECRET\nRUN npm run build\n"
        "FROM nginx\nCOPY --from=build /app /usr/share/nginx/html\n",
        encoding="utf-8",
    )
    rules = _bs_rules(BuildSecretGuard().run(tmp_path, _bs_prof(tmp_path)))
    assert ("build-secret/client-prefixed-secret", "medium") in rules

def test_build_secret_backend_bare_secret(tmp_path: Path) -> None:
    # backend-only stack: a bare ARG DB_PASSWORD baked into an image layer fires (the §1 verifier).
    (tmp_path / "Dockerfile").write_text(
        "FROM python:3.12\nARG DB_PASSWORD\nRUN ./build.sh\n", encoding="utf-8"
    )
    rules = _bs_rules(BuildSecretGuard().run(tmp_path, mkprofile(tmp_path, features={"docker"})))
    assert ("build-secret/secret-build-arg", "high") in rules

def test_build_secret_bare_token_fires(tmp_path: Path) -> None:
    # Marconi's decision: bare *_TOKEN in a Dockerfile is almost always a credential.
    (tmp_path / "Dockerfile").write_text(
        "FROM python:3.12\nARG GITHUB_TOKEN\nRUN ./build.sh\n", encoding="utf-8"
    )
    rules = _bs_rules(BuildSecretGuard().run(tmp_path, mkprofile(tmp_path, features={"docker"})))
    assert ("build-secret/secret-build-arg", "high") in rules

def test_build_secret_token_substring_no_fp(tmp_path: Path) -> None:
    # Empirical FP (flagship backend Dockerfiles): TIKTOKEN_CACHE_DIR contains "TOKEN" mid-word
    # and its value is a path — must stay silent. The bare-token match is word-boundary anchored.
    (tmp_path / "Dockerfile").write_text(
        "FROM python:3.12\nARG TIKTOKEN_CACHE_DIR\nENV TIKTOKEN_CACHE_DIR=/app/.tiktoken_cache\n",
        encoding="utf-8",
    )
    assert BuildSecretGuard().run(tmp_path, mkprofile(tmp_path, features={"docker"})) == []

def test_build_secret_bare_key_silent(tmp_path: Path) -> None:
    # Marconi's decision: bare KEY stays out (noisy: BUILD_KEY / CACHE_KEY).
    (tmp_path / "Dockerfile").write_text(
        "FROM python:3.12\nARG BUILD_KEY\nARG CACHE_KEY\nRUN ./build.sh\n", encoding="utf-8"
    )
    assert BuildSecretGuard().run(tmp_path, mkprofile(tmp_path, features={"docker"})) == []

def test_build_secret_env_value_heuristic(tmp_path: Path) -> None:
    # benign literal (SECRET_VERSION=2) skipped; empty + opaque values flagged.
    (tmp_path / "Dockerfile").write_text(
        "FROM python:3.12\nENV SECRET_VERSION=2\nENV API_SECRET=\nENV DB_PASSWORD=hunter2\n",
        encoding="utf-8",
    )
    locs = sorted(
        f.location.split(":")[-1]
        for f in BuildSecretGuard().run(tmp_path, mkprofile(tmp_path, features={"docker"}))
    )
    assert locs == ["3", "4"]  # API_SECRET= (line 3) + DB_PASSWORD=hunter2 (line 4); SECRET_VERSION=2 skipped

def test_build_secret_dockerfile_suffix_scanned(tmp_path: Path) -> None:
    # *.dockerfile is scanned (no regression vs the absorbed docker-build-arg-secret guard).
    (tmp_path / "service.dockerfile").write_text(
        "FROM python:3.12\nARG DB_PASSWORD\n", encoding="utf-8"
    )
    rules = _bs_rules(BuildSecretGuard().run(tmp_path, mkprofile(tmp_path, features={"docker"})))
    assert ("build-secret/secret-build-arg", "high") in rules

def test_build_secret_public_anon_key_is_clean_negative(tmp_path: Path) -> None:
    (tmp_path / "frontend").mkdir()
    (tmp_path / "frontend" / "db.ts").write_text(
        "const k = import.meta.env.VITE_SUPABASE_ANON_KEY\n", encoding="utf-8"
    )
    (tmp_path / "Dockerfile").write_text(
        "FROM node\nARG VITE_SUPABASE_ANON_KEY\nRUN vite build\n", encoding="utf-8"
    )
    assert BuildSecretGuard().run(tmp_path, _bs_prof(tmp_path)) == []

def test_build_secret_pragma_opt_out(tmp_path: Path) -> None:
    (tmp_path / "Dockerfile").write_text(
        "FROM node\nARG VITE_APP_SECRET  # security: allow-build-secret\nRUN npm run build\n",
        encoding="utf-8",
    )
    assert BuildSecretGuard().run(tmp_path, _bs_prof(tmp_path)) == []

def test_build_secret_silent_on_substring_names(tmp_path: Path) -> None:
    # #423 FP-bait: the bare token must be a whole segment — AUTHOR (AUTH...) and
    # TOKENIZERS_PARALLELISM (TOKEN...) are not secrets; the benign value also skips ARG.
    (tmp_path / "Dockerfile").write_text(
        "FROM python:3.12\n"
        "ARG AUTHOR\n"
        "ARG TOKENIZERS_PARALLELISM=false\n"
        "RUN ./build.sh\n",
        encoding="utf-8",
    )
    prof = mkprofile(tmp_path, features={"docker"}, python_dirs=["."])
    assert BuildSecretGuard().run(tmp_path, prof) == []

def test_build_secret_still_flags_bare_arg_secret(tmp_path: Path) -> None:
    # regression: a real bare secret ARG still fires.
    (tmp_path / "Dockerfile").write_text(
        "FROM python:3.12\nARG DB_PASSWORD\nRUN ./build.sh\n", encoding="utf-8"
    )
    prof = mkprofile(tmp_path, features={"docker"}, python_dirs=["."])
    assert len(BuildSecretGuard().run(tmp_path, prof)) >= 1

def test_build_secret_arg_with_benign_default_still_fires(tmp_path: Path) -> None:
    # PR #447 review: an ARG's build-time default is a placeholder (the real secret arrives via
    # --build-arg), so a benign-looking default must NOT suppress it — the value heuristic is
    # ENV-only. `ARG DB_PASSWORD=0` still fires.
    (tmp_path / "Dockerfile").write_text(
        "FROM python:3.12\nARG DB_PASSWORD=0\nRUN ./build.sh\n", encoding="utf-8"
    )
    prof = mkprofile(tmp_path, features={"docker"}, python_dirs=["."])
    assert len(BuildSecretGuard().run(tmp_path, prof)) >= 1

def test_build_secret_not_applicable_without_frontend_or_docker(tmp_path: Path) -> None:
    assert BuildSecretGuard().applies(mkprofile(tmp_path, features={"python"})) is False



def test_build_secret_credentials_and_authorization_args_fire(tmp_path: Path) -> None:
    # Regression (#447 review): the whole-segment boundary that keeps AUTHOR and
    # TIKTOKEN_CACHE_DIR silent also rejected CRED and AUTH, which are PREFIXES of the real
    # names — so `ARG AWS_CREDENTIALS` and `ARG AUTHORIZATION=Bearer sk-live-abc` went silent
    # while `NPM_TOKEN` still fired. The full words are now listed in their own right.
    (tmp_path / "Dockerfile").write_text(
        "FROM python:3.12\n"
        "ARG AWS_CREDENTIALS\n"
        "ARG AUTHORIZATION=Bearer sk-live-abc\n"
        "ARG GOOGLE_APPLICATION_CREDENTIALS\n"
        "ARG GCP_CREDENTIAL_JSON\n"
        "ARG AUTHENTICATION_KEY\n",
        encoding="utf-8",
    )
    assert len(BuildSecretGuard().run(tmp_path, _bs_prof(tmp_path))) == 5


def test_build_secret_author_and_tiktoken_stay_silent(tmp_path: Path) -> None:
    # FP-bait, and exactly what the segment boundary exists for: a name that merely CONTAINS a
    # token. AUTHOR is not AUTHORIZATION; TIKTOKEN is not a TOKEN.
    (tmp_path / "Dockerfile").write_text(
        "FROM python:3.12\n"
        "ARG AUTHOR\nARG AUTHORS\nARG TIKTOKEN_CACHE_DIR\nARG TOKENIZERS_PARALLELISM\n",
        encoding="utf-8",
    )
    assert BuildSecretGuard().run(tmp_path, _bs_prof(tmp_path)) == []


def test_build_secret_ambiguous_name_with_config_value_stays_silent(tmp_path: Path) -> None:
    # FP-bait (#447 review): CREDENTIALS/AUTHORIZATION/AUTHENTICATION were added as whole words so
    # `AWS_CREDENTIALS` would fire, but the full words also name CONFIG DESCRIPTORS. The value is
    # the discriminator: a path, a URL or a plain mechanism/vendor word embeds no secret material.
    # `GOOGLE_APPLICATION_CREDENTIALS=<path>` is the RECOMMENDED practice — flagging it would fire
    # on the fix.
    (tmp_path / "Dockerfile").write_text(
        "FROM python:3.12\n"
        "ARG AUTHENTICATION_METHOD=oauth2\n"
        "ENV AUTHENTICATION_PROVIDER=google\n"
        "ARG GOOGLE_APPLICATION_CREDENTIALS=/secrets/gcp-key.json\n"
        "ENV GOOGLE_APPLICATION_CREDENTIALS=/secrets/gcp-key.json\n"
        "ARG AUTHORIZATION_ENDPOINT=https://accounts.example.com/o/oauth2/auth\n",
        encoding="utf-8",
    )
    assert BuildSecretGuard().run(tmp_path, _bs_prof(tmp_path)) == []


def test_build_secret_ambiguous_name_with_secret_value_still_fires(tmp_path: Path) -> None:
    # The other direction: the value gate is scoped to the ambiguous full words and must not cost
    # a single true positive the value actually corroborates — an absent value (a placeholder ARG
    # whose real secret arrives via `--build-arg`) or embedded key material.
    (tmp_path / "Dockerfile").write_text(
        "FROM python:3.12\n"
        "ARG AWS_CREDENTIALS\n"
        "ARG AUTHORIZATION=Bearer sk-live-abc\n"
        "ARG GCP_CREDENTIAL_JSON\n"
        "ARG AUTHENTICATION_KEY\n"
        "ENV AUTHENTICATION_KEY=aG9sZFRoaXNJc1JlYWxseVNlY3JldA\n",
        encoding="utf-8",
    )
    assert len(BuildSecretGuard().run(tmp_path, _bs_prof(tmp_path))) == 5


def test_build_secret_hard_token_never_value_gated(tmp_path: Path) -> None:
    # The value gate applies ONLY to the ambiguous full words. A hard token (TOKEN/PASSWORD/
    # SECRET/...) fires on the name alone, whatever its default looks like, for ARG and ENV alike.
    (tmp_path / "Dockerfile").write_text(
        "FROM python:3.12\n"
        "ARG NPM_TOKEN=abc123\n"
        "ARG DB_PASSWORD=0\n"
        "ARG AUTH_TOKEN=oauth2\n",
        encoding="utf-8",
    )
    assert len(BuildSecretGuard().run(tmp_path, _bs_prof(tmp_path))) == 3


def test_build_secret_ambiguous_value_gate_does_not_wave_through_real_secrets(tmp_path: Path) -> None:
    # THE #447 re-review CRITICAL. The value classifier called real secrets benign: any short
    # single-case alnum value passed the "descriptor" test, which is the shape of most short real
    # secrets, and a URL was benign no matter what userinfo it carried. `AUTHENTICATION_KEY` is
    # listed as a PRESERVED true positive in the previous fix's own message — it was preserved only
    # while the value was EMPTY. A value now silences a finding only when it is RECOGNISED benign.
    (tmp_path / "Dockerfile").write_text(
        "FROM python:3.12\n"
        "ARG AUTHENTICATION_KEY=hunter2\n"
        "ARG AUTHENTICATION=hunter2\n"
        "ENV CREDENTIALS=abc123def\n"
        "ARG AUTHORIZATION=https://user:pass@host/cb\n"
        "ARG CREDENTIALS_JSON=deadbeefcafe1234\n"
        "ENV AUTHORIZATION=aGVsbG8vd29ybGQ\n",
        encoding="utf-8",
    )
    assert len(BuildSecretGuard().run(tmp_path, _bs_prof(tmp_path))) == 6


def test_build_secret_url_with_userinfo_is_not_a_benign_env_value(tmp_path: Path) -> None:
    # The ENV benign-value gate runs BEFORE the name check, so treating any `https?://...` as
    # benign silenced a hard-token name outright — a DSN with `user:pass@` in it IS the secret.
    # A material name's pointer admission is built from the same URL arm (`_POINTER`, #509), so it
    # keeps the rule too: `AUTHENTICATION_KEY` admits a URL, never one carrying credentials.
    (tmp_path / "Dockerfile").write_text(
        "FROM python:3.12\n"
        "ENV DB_PASSWORD=https://user:pass@host/x\n"
        "ENV DATABASE_SECRET=postgresql://u:p@db:5432/app\n"
        "ARG AUTHENTICATION_KEY=https://user:pass@vault.example/k\n",
        encoding="utf-8",
    )
    assert len(BuildSecretGuard().run(tmp_path, _bs_prof(tmp_path))) == 3


def test_build_secret_recognised_benign_values_stay_silent(tmp_path: Path) -> None:
    # FP-bait for the tightened gate — the descriptor shapes that must survive it: a known
    # mechanism word on a bare ambiguous name, a vendor word on a name that SELECTS a mechanism,
    # absolute and relative credential-FILE pointers (the recommended practice), a userinfo-free
    # URL, a flag, and a value containing `sk-`/`risk-` which is a word, not a Stripe key prefix.
    (tmp_path / "Dockerfile").write_text(
        "FROM python:3.12\n"
        "ARG AUTHENTICATION=basic\n"
        "ENV AUTHORIZATION=none\n"
        "ARG AUTHENTICATION_METHOD=oauth2\n"
        "ENV AUTHENTICATION_PROVIDER=google\n"
        "ARG AUTHENTICATION_MODE=risk-based\n"
        "ARG GOOGLE_APPLICATION_CREDENTIALS=/secrets/gcp-key.json\n"
        "ARG CREDENTIALS=config/gcp-key.json\n"
        "ENV CREDENTIALS=./secrets/key\n"
        "ARG AUTHORIZATION_ENDPOINT=https://accounts.example.com/o/oauth2/auth\n"
        "ENV AUTHENTICATION_ENABLED=1\n"
        "ARG AUTHOR=jane\n",
        encoding="utf-8",
    )
    assert BuildSecretGuard().run(tmp_path, _bs_prof(tmp_path)) == []


def test_build_secret_credential_markers_are_word_boundaried(tmp_path: Path) -> None:
    # Both directions of the marker fix in one file: the marker prefixes are `\b`-anchored, so an
    # ordinary word containing `sk-` (`task-based`) is not a Stripe key — while every real marker
    # form still overrides the benign shapes, including a lowercase `bearer`, `sk_`, a mid-string
    # `AKIA...`, a two-segment JWT and a PEM header.
    (tmp_path / "Dockerfile").write_text(
        "FROM python:3.12\n"
        "ARG AUTHENTICATION_METHOD=task-based\n"
        "ARG AUTHORIZATION=bearer abc12345\n"
        "ENV CREDENTIALS=sk_live_abcdefgh\n"
        "ARG CREDENTIALS_TYPE=foo-AKIAIOSFODNN7EXAMPLE\n"
        "ENV AUTHORIZATION=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0\n"
        'ARG AUTHENTICATION_MODE="-----BEGIN RSA PRIVATE KEY-----"\n',
        encoding="utf-8",
    )
    assert len(BuildSecretGuard().run(tmp_path, _bs_prof(tmp_path))) == 5


@pytest.mark.parametrize(
    "value",
    [
        "keycloak",   # the three the #447 gate measured going 0 -> 1
        "azure-ad",
        "cognito",
        "auth0",
        "okta",
    ],
)
def test_build_secret_vendor_value_on_a_bare_ambiguous_name_is_benign(tmp_path: Path, value: str) -> None:
    # An identity-provider NAME is a descriptor, not key material. The vendor vocabulary was
    # originally omitted on the reasoning that a vendor value rides on the descriptor NAME rule
    # (`*_PROVIDER=google`) — true only when the name HAS such a suffix. On a BARE ambiguous name
    # it does not, and these fired as embedded secrets: the unfixable-CI-finding class the
    # benign-value discrimination exists to prevent.
    (tmp_path / "Dockerfile").write_text(f"FROM python:3.12\nARG AUTHENTICATION={value}\n", encoding="utf-8")
    assert BuildSecretGuard().run(tmp_path, _bs_prof(tmp_path)) == []


@pytest.mark.parametrize(
    ("name", "value"),
    [
        # THE TRADED-AGAINST DIRECTION. The vendor list WIDENS what counts as benign, so its risk
        # is silencing a real secret. `swordfish` is the case that matters: lexically identical in
        # shape to `keycloak` (one lowercase word), and separated only by being in no list — which
        # is exactly why this is a closed enumeration and not a shape rule.
        ("AUTHORIZATION", "swordfish"),
        ("AUTHENTICATION_KEY", "hunter2"),
        ("CREDENTIALS", "1234567890123456"),
        ("NPM_TOKEN", "abc123def456"),
        # ...and the direction that actually touches the widened surface. A vocabulary word is a
        # SELECTOR value ("which provider/scheme"), so it may only silence a name that HAS a
        # selector reading. On a name that says the variable HOLDS material there is none, and a
        # listed word is just a weak secret: `AUTHENTICATION_KEY` is this guard's own canonical
        # must-still-fire name (#447 gate, M1).
        ("AUTHENTICATION_KEY", "apple"),        # vendor word — the class the vendor list opened
        ("AUTHORIZATION_KEY", "google"),
        ("CREDENTIALS_KEY", "okta"),
        ("AUTHENTICATION_KEYS", "duo"),
        ("CREDENTIALS_PIN", "clerk"),
        ("AUTHENTICATION_HASH", "apple"),
        ("AUTHORIZATION_SALT", "google"),
        ("CREDENTIALS_SIGNATURE", "okta"),
        ("AUTHENTICATION_PASSPHRASE", "apple"),
        # A trailing digit run is part of the head noun, not a new segment — the anchor's `\d*`.
        ("AUTHENTICATION_KEY64", "apple"),
        # mechanism words — the SAME class, open since the vocabulary was introduced, not just
        # since the vendor words were added. `AUTHENTICATION_KEY=password` is the worst of them.
        ("AUTHENTICATION_KEY", "password"),
        ("CREDENTIALS_KEY", "basic"),
        ("AUTHORIZATION_KEY", "session"),
        ("AUTHENTICATION_KEY", "none"),
        # THE CLOSED LIST IS CLOSED. `keycloack` is a typo of a listed vendor and is lexically
        # indistinguishable from one; membership, not shape, is what silences — so it stays
        # material. This fails the moment anyone replaces the enumeration with a shape rule.
        ("AUTHORIZATION", "keycloack"),
        ("AUTHENTICATION", "keycloack"),
        # `_ALGORITHM` is not a selector suffix, so this is a BARE name and the closed list decides:
        # an unlisted algorithm fires. The design doc discloses it and points to `*_DIGEST_TYPE`
        # instead (#960 round 2); adding the suffix would widen the all-letter residual to a new name.
        ("CREDENTIALS_DIGEST_ALGORITHM", "bcrypt"),
    ],
)
def test_build_secret_material_values_still_fire(tmp_path: Path, name: str, value: str) -> None:
    (tmp_path / "Dockerfile").write_text(f"FROM python:3.12\nARG {name}={value}\n", encoding="utf-8")
    assert len(BuildSecretGuard().run(tmp_path, _bs_prof(tmp_path))) == 1, f"{name}={value}"


@pytest.mark.parametrize(
    ("name", "value"),
    [
        # FP-bait for the material-name gate itself: a name that says KEY but ALSO carries an
        # explicit selector segment still has a selector reading, so the vocabulary still applies.
        ("AUTHENTICATION_KEY_PROVIDER", "google"),
        ("CREDENTIALS_KEY_TYPE", "oauth2"),
        ("AUTHENTICATION_KEY_MODE", "none"),
        # `KEYCLOAK` is not a `KEY` segment — the ANCHORING keeps it out (here specifically the
        # leading `_`: `KEY` sits at position 0, so the `$` end-anchor never comes into it — the
        # case survives a drop-`$` mutant and dies only under full de-anchoring; #447 agentic gate,
        # L1). The name must at least REACH `_MATERIAL_NAME` for that to be what it pins:
        # `AUTHENTICATION_KEYCLOAK_MODE` ends in `_MODE`, so `_DESCRIPTOR_NAME` short-circuits first
        # and the case passed whatever the boundary did — it survived a mutant that moved 6
        # behaviours (#447 re-gate, L3). This name has no selector suffix, so it does reach the gate.
        ("KEYCLOAK_CREDENTIALS", "google"),
        # The `$` end-anchor's own bait: a segment that STARTS with a material word but names no
        # material, which the deleted `(?![A-Za-z])` lookahead used to exclude and `$` now carries
        # alone. Under a drop-`$` mutant all three flip to firing (#447 agentic gate, L2). This bait
        # used to be `AUTHENTICATION_KEYSTORE`/`CREDENTIALS_KEYRING`, which were silent only because
        # the material list lacked them; #509 (absorbing #514) added them, so they moved to the
        # fires side and these non-material compounds took over the anchor.
        ("CREDENTIALS_KEYVAULT", "azure"),
        ("AUTHENTICATION_KEYCLOAK", "google"),
        ("CREDENTIALS_PINNING", "enabled"),
        # THE MATERIAL WORD MUST BE THE HEAD NOUN. Mid-name it is a QUALIFIER — "credentials for
        # the key vault", "authentication by SSH key", "which hash algorithm" — and those names
        # keep their selector reading. Matching the segment in any position fired a CI-blocking
        # HIGH on all of these, the unfixable-finding class this batch exists to remove
        # (#447 re-gate, M3). `_ALGORITHM`/`_ALG` are absent from `_DESCRIPTOR_NAME`, so the last
        # two have no selector suffix to rescue them and rest entirely on the anchor.
        ("SSH_KEY_AUTHENTICATION", "enabled"),
        ("KEY_VAULT_CREDENTIALS", "azure"),
        ("KEY_MANAGEMENT_AUTHENTICATION", "aws"),
        ("PIN_AUTHENTICATION", "disabled"),
        ("CREDENTIALS_HASH_ALGORITHM", "scram"),
        ("AUTHENTICATION_SIGNATURE_ALGORITHM", "hmac"),
        # Three representatives of the anchor's cost, pinned so it is a decision and not a drift: a
        # key's ID and a key COUNT are not the key, and `KEY_AUTHENTICATION` reads as "authentication
        # by key" — all three are selector names, and all three were material while the match floated.
        # THESE THREE ARE NOT THE WHOLE COST. The bound is positional, so `<AMBIGUOUS>_<MATERIAL>_
        # <TAIL>` falls out of it for ANY non-selector tail: `AUTHENTICATION_KEY_VALUE=password` and
        # `AUTHENTICATION_KEY_V2=password` are silent too (987 of 987 enumerated names, §Known
        # bypasses in wiki/guards/build-secret.md, #447 agentic gate M1). Bounded to vocabulary
        # values — every one of those names still fires on `=hunter2`. #509 (absorbing #514) left it
        # open on purpose: closing it needs a tail vocabulary (`ID`/`COUNT` vs `VALUE`/`V2`), which
        # reopens the M3 class these three rows pin.
        ("AUTHENTICATION_KEY_ID", "apple"),
        ("AUTHENTICATION_KEYS_COUNT", "apple"),
        ("KEY_AUTHENTICATION", "apple"),
        # Closed-list self-consistency: siblings of words already listed. `pingid`/`pingfederate`
        # were listed without `pingone`, `entra` without `entra-id`, `azure-ad`/`azuread` without
        # `azure_ad` — the same vendor, spelled the way the product actually is (#447 gate, L1).
        ("AUTHENTICATION", "pingone"),
        ("AUTHENTICATION", "entra-id"),
        ("AUTHENTICATION", "azure_ad"),
        # `x509` is in the mechanism vocabulary but has THREE trailing digits, so the word shape
        # rejected it and it could never match. A closed vocabulary is matched by identity; the
        # shape only ever bounded the open-ended name-selector arm (#447 gate, I1).
        ("AUTHENTICATION", "x509"),
    ],
)
def test_build_secret_selector_readings_stay_silent(tmp_path: Path, name: str, value: str) -> None:
    (tmp_path / "Dockerfile").write_text(f"FROM python:3.12\nARG {name}={value}\n", encoding="utf-8")
    assert BuildSecretGuard().run(tmp_path, _bs_prof(tmp_path)) == [], f"{name}={value}"


@pytest.mark.parametrize(
    ("name", "value"),
    [
        # #509. A selector suffix used to wave through any word-SHAPED value, and the shape allowed
        # two trailing digits so `oauth2` would pass. `<word><1-2 digits>` is also the commonest weak
        # password, so every one of these was a "mechanism name". A digit-bearing value on a selector
        # name is now recognised by identity (the vocabulary, a version) or not at all.
        ("CREDENTIALS_TYPE", "hunter2"),
        ("AUTHENTICATION_SOURCE", "trustno1"),
        ("AUTHORIZATION_MODE", "letmein1"),
        ("CREDENTIALS_PROVIDER", "admin12"),
        ("AUTHENTICATION_FORMAT", "welcome1"),
        ("AUTHENTICATION_VERSION", "secret12"),
        ("AUTHENTICATION_METHOD", "hunter2"),   # the instance #447 disclosed as a residual
        # Digits mid-word already fired; pinned here because the silent test below NARROWS this same
        # arm (Rule 1: the narrowing must not cost these).
        ("CREDENTIALS_TYPE", "abc123def"),
        ("AUTHORIZATION_SCHEME", "p4ssw0rd"),
        # The version arm's own bait (#960 review): a `v` in front of a PIN is not a version tag. The
        # undotted form takes two digits at most, so `v1234` and `v123` are material; the four-digit
        # exception is a calendar year only (round 4), so a PIN that is not a year still fires.
        ("CREDENTIALS_TYPE", "v1234"),
        ("AUTHENTICATION_VERSION", "v123"),
        ("CREDENTIALS_TYPE", "v2100"),         # above the 19xx/20xx year range
        ("AUTHENTICATION_VERSION", "v1899"),   # below it
    ],
)
def test_build_secret_selector_name_does_not_admit_a_digit_bearing_password(
    tmp_path: Path, name: str, value: str,
) -> None:
    (tmp_path / "Dockerfile").write_text(
        f"FROM python:3.12\nARG {name}={value}\nENV {name}={value}\n", encoding="utf-8",
    )
    assert len(BuildSecretGuard().run(tmp_path, _bs_prof(tmp_path))) == 2, f"{name}={value}"


@pytest.mark.parametrize(
    ("name", "value"),
    [
        # The narrowing half of #509, and the FP-bait for the digit-free shape. The selector arm never
        # consulted the vocabulary, so a listed word the shape rejected FIRED on every selector name:
        # `x509` (three trailing digits) on all 48 of them, a CI-blocking HIGH on ordinary auth config.
        ("AUTHENTICATION_METHOD", "x509"),
        ("AUTHENTICATION_METHOD", "scram-sha-256"),
        ("CREDENTIALS_FORMAT", "sha256"),
        ("AUTHENTICATION_VERSION", "1.2"),
        # The shape no longer admits a digit, so every digit-bearing mechanism rides on the list now.
        ("AUTHENTICATION_METHOD", "ntlmv2"),
        ("AUTHENTICATION_METHOD", "oauth2"),
        ("CREDENTIALS_FORMAT", "pkcs12"),
        ("CREDENTIALS_SOURCE", "ec2"),
        ("AUTHENTICATION_PROVIDER", "auth0"),
        ("AUTHENTICATION_VERSION", "v2"),
        # The traded-against side of the `v1234` narrowing (#960 review): two undotted digits, a
        # dotted four-digit major (calendar versioning), a dotted `v` form and an undotted `v` year
        # (round-4 review, R4-M1) all still read as versions.
        ("AUTHENTICATION_VERSION", "v10"),
        ("CREDENTIALS_FORMAT", "2024.1"),
        ("AUTHENTICATION_VERSION", "v1.2.3"),
        ("AUTHENTICATION_VERSION", "v2024"),
        ("AUTHENTICATION_VERSION", "v1999"),   # the year range's lower half
        # The selector form of an algorithm or format on a material noun. The bare material name
        # (`CREDENTIALS_DIGEST=sha256`, `AUTHENTICATION_KEYSTORE=pkcs12`) fires, before and after #509,
        # because a name that holds material admits only a pointer or a boolean. The design doc points
        # to the `*_TYPE` form instead, so it must read as config, an unlisted algorithm included.
        ("CREDENTIALS_DIGEST_TYPE", "bcrypt"),
        ("AUTHENTICATION_KEYPAIR_TYPE", "ed25519"),
        ("AUTHENTICATION_KEYSTORE_TYPE", "pkcs12"),
        # `_ALGORITHM` is no selector suffix: this passes only because `sha256` is listed (`=bcrypt`
        # fires, pinned in the still-fires test).
        ("CREDENTIALS_DIGEST_ALGORITHM", "sha256"),
        # ...and an unlisted, digit-free word still passes the open-ended shape.
        ("AUTHENTICATION_PROVIDER", "ory"),
    ],
)
def test_build_secret_selector_name_admits_a_listed_or_versioned_mechanism(
    tmp_path: Path, name: str, value: str,
) -> None:
    (tmp_path / "Dockerfile").write_text(
        f"FROM python:3.12\nARG {name}={value}\nENV {name}={value}\n", encoding="utf-8",
    )
    assert BuildSecretGuard().run(tmp_path, _bs_prof(tmp_path)) == [], f"{name}={value}"


@pytest.mark.parametrize(
    "line",
    [
        # The digit-bearing mechanism words live in the SHARED vocabulary, so they also silence a bare
        # ambiguous name. Every one of these fired before #509; none is a secret here either (#960
        # review, M1: the narrowing was real, and untested).
        "ARG AUTHENTICATION=sha256",
        "ARG AUTHENTICATION=md5",
        "ARG AUTHENTICATION=ntlmv2",
        "ARG CREDENTIALS=s3",
        "ARG AUTHORIZATION=ec2",
        "ENV CREDENTIALS=k8s",
    ],
)
def test_build_secret_bare_name_admits_a_listed_digit_bearing_mechanism(tmp_path: Path, line: str) -> None:
    (tmp_path / "Dockerfile").write_text(f"FROM python:3.12\n{line}\n", encoding="utf-8")
    assert BuildSecretGuard().run(tmp_path, _bs_prof(tmp_path)) == [], line


@pytest.mark.parametrize(
    "line",
    [
        # The traded-against direction of the test above: a bare name recognises by exact IDENTITY
        # only, so a longer list lets no digit-bearing password through. An unlisted `<word><digits>`
        # still fires, and so does a near miss of a listed word.
        "ARG AUTHENTICATION=hunter2",
        "ARG CREDENTIALS=admin12",
        "ENV AUTHORIZATION=letmein1",
        "ARG AUTHENTICATION=sha257",
        "ARG CREDENTIALS=s33",
    ],
)
def test_build_secret_bare_name_still_fires_on_an_unlisted_digit_bearing_word(
    tmp_path: Path, line: str,
) -> None:
    (tmp_path / "Dockerfile").write_text(f"FROM python:3.12\n{line}\n", encoding="utf-8")
    assert len(BuildSecretGuard().run(tmp_path, _bs_prof(tmp_path))) == 1, line


@pytest.mark.parametrize(
    ("name", "value"),
    [
        # #514, absorbed into #509: head nouns missing from the old six-word material list got no
        # bound, so the WHOLE vocabulary silenced them. One row per added word.
        ("AUTHENTICATION_SEED", "apple"),
        ("CREDENTIALS_NONCE", "google"),
        ("CREDENTIALS_DIGEST", "basic"),
        ("AUTHENTICATION_HMAC", "okta"),
        ("CREDENTIALS_PHRASE", "password"),
        ("AUTHENTICATION_KEYSTORE", "apple"),   # both were pinned SILENT, as the `$` bait, until #509
        ("CREDENTIALS_KEYRING", "google"),
        ("AUTHORIZATION_KEYPAIR", "none"),
        ("AUTHENTICATION_KEYFILE", "apple"),
        ("CREDENTIALS_PRIVKEY", "duo"),
        ("AUTHENTICATION_SECRETKEY", "apple"),
        # #514's second instance: the short-number knob and the env words ran BEFORE the name was
        # read, so they silenced even a name that was on the list. On `ARG` that name now decides
        # first, the same as a hard token (`ARG DB_PASSWORD=test` has always fired).
        ("AUTHENTICATION_KEY", "test"),
        ("AUTHENTICATION_KEY", "local"),
        ("AUTHENTICATION_KEY", "dev"),
        ("AUTHENTICATION_KEY", "123456"),
        ("AUTHENTICATION_KEY", "0"),
        ("AUTHENTICATION_PIN", "1234"),
    ],
)
def test_build_secret_material_name_is_read_before_any_value_recogniser(
    tmp_path: Path, name: str, value: str,
) -> None:
    (tmp_path / "Dockerfile").write_text(f"FROM python:3.12\nARG {name}={value}\n", encoding="utf-8")
    assert len(BuildSecretGuard().run(tmp_path, _bs_prof(tmp_path))) == 1, f"{name}={value}"


@pytest.mark.parametrize(
    "line",
    [
        # FP-bait for the widening above: a material name still admits a POINTER to the material
        # (absolute path, relative path, userinfo-free URL) and a boolean. None of them is the key.
        "ARG AUTHENTICATION_KEYFILE=/run/secrets/k.pem",
        "ARG CREDENTIALS_KEYSTORE=config/keystore.jks",
        "ARG AUTHENTICATION_SEED=./seed.txt",
        "ARG AUTHENTICATION_KEY=https://vault.example/k",
        "ARG AUTHENTICATION_KEY=true",
        # A decision, not a gap: the ENV benign-value gate runs before any name check, for EVERY
        # name (`ENV DB_PASSWORD=test` is silent too), so #509 changes `ARG` only.
        "ENV AUTHENTICATION_KEY=local",
        "ENV AUTHENTICATION_PIN=1234",
    ],
)
def test_build_secret_material_name_still_admits_a_pointer_or_boolean(tmp_path: Path, line: str) -> None:
    (tmp_path / "Dockerfile").write_text(f"FROM python:3.12\n{line}\n", encoding="utf-8")
    assert BuildSecretGuard().run(tmp_path, _bs_prof(tmp_path)) == [], line


@pytest.mark.parametrize(
    "line",
    [
        # #960 round-6 review (R6-M1): two head nouns the #509 list still lacked. Without them a numeric
        # value fell through to the short-number knob and each of these was silent (checked: 0 findings
        # under the pre-fix regex, 1 under this one).
        "ARG AUTHENTICATION_PASSCODE=1234",
        "ARG AUTHENTICATION_PASSCODE=194875",
        "ARG CREDENTIALS_PSK=123456",
        "ARG AUTHENTICATION_PASSCODE2=1234",   # the optional trailing digit run, same as `_KEY64`
        # NOT a discriminating row: an opaque hex value fired before the fix too (the generic
        # embedded-material fallthrough), pinned here only so the material reading and the old
        # reading agree on it.
        "ARG CREDENTIALS_PSK=482913a7",
    ],
)
def test_build_secret_passcode_and_psk_are_material_names(tmp_path: Path, line: str) -> None:
    (tmp_path / "Dockerfile").write_text(f"FROM python:3.12\n{line}\n", encoding="utf-8")
    assert len(BuildSecretGuard().run(tmp_path, _bs_prof(tmp_path))) == 1, line


@pytest.mark.parametrize(
    "line",
    [
        # FP-bait for that widening: the material word mid-name is a QUALIFIER and the selector
        # reading survives (`$` anchor), a pointer is still admitted, and `RECOVERY` is deliberately
        # NOT on the list because `=enabled` is a feature toggle (the OTP/TOTP carve-out).
        "ARG AUTHENTICATION_PASSCODE_METHOD=sms",
        "ARG CREDENTIALS_PSK_TYPE=hex",
        "ARG AUTHENTICATION_PASSCODE=/run/secrets/passcode",
        "ARG CREDENTIALS_PSK=true",
        "ARG AUTHENTICATION_RECOVERY=enabled",
    ],
)
def test_build_secret_passcode_psk_neighbours_stay_silent(tmp_path: Path, line: str) -> None:
    (tmp_path / "Dockerfile").write_text(f"FROM python:3.12\n{line}\n", encoding="utf-8")
    assert BuildSecretGuard().run(tmp_path, _bs_prof(tmp_path)) == [], line
