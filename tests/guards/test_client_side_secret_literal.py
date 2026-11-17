from __future__ import annotations

from agentsec.findings import Finding
from agentsec.guards.client_side_secret_literal import ClientSideSecretLiteralGuard
from tests.guards._common import *  # noqa: F401,F403


def test_client_side_secret_literal_fires_openai_project_key(tmp_path: Path) -> None:
    (tmp_path / "api.ts").write_text(
        'const h = "sk-proj-FSAFCREDACTEDOVY7EfDDXIMrVayZub7TakA";\n', encoding="utf-8"
    )
    findings = ClientSideSecretLiteralGuard().run(tmp_path, mkprofile(tmp_path, features={"frontend"}))
    assert len(findings) == 1
    assert findings[0].rule == "client-side-secret-literal/hardcoded-api-key-literal"
    assert findings[0].severity == "high"


def test_client_side_secret_literal_fires_aws_and_github(tmp_path: Path) -> None:
    (tmp_path / "cfg.js").write_text(
        'const AWS = "AKIAIOSFODNN7EXAMPLE";\n'
        'const gh = "ghp_012345678901234567890123456789abcdef";\n',
        encoding="utf-8",
    )
    findings = ClientSideSecretLiteralGuard().run(tmp_path, mkprofile(tmp_path, features={"javascript"}))
    assert len(findings) == 2


def test_client_side_secret_literal_fires_google_key(tmp_path: Path) -> None:
    (tmp_path / "maps.jsx").write_text(
        'const key = "AIzaSyD-abc123DEF456ghi789JKL012mno345PQ";\n', encoding="utf-8"
    )
    findings = ClientSideSecretLiteralGuard().run(tmp_path, mkprofile(tmp_path, features={"frontend"}))
    assert len(findings) == 1


def test_client_side_secret_literal_silent_short_prefix(tmp_path: Path) -> None:
    # a BEM/skeleton-loader class and a bare "sk-" fragment must not match
    (tmp_path / "ui.tsx").write_text(
        'const cls = "sk-loading-spinner-container-wrapper";\nconst p = "sk-";\n',
        encoding="utf-8",
    )
    assert ClientSideSecretLiteralGuard().run(tmp_path, mkprofile(tmp_path, features={"frontend"})) == []


def test_client_side_secret_literal_silent_slack_word_slug(tmp_path: Path) -> None:
    # a hyphenated word-slug starting with a Slack prefix is not a token (regression for #488 High)
    (tmp_path / "ui.ts").write_text(
        'const cls = "xoxp-not-a-real-token-just-a-css-slug-name-example";\n', encoding="utf-8"
    )
    assert ClientSideSecretLiteralGuard().run(tmp_path, mkprofile(tmp_path, features={"frontend"})) == []


def test_client_side_secret_literal_fires_real_slack_token(tmp_path: Path) -> None:
    # a structured Slack bot token (numeric IDs + alnum secret) still fires
    (tmp_path / "slack.js").write_text(
        'const t = "xoxb-1234567890-1234567890123-AbCdEfGhIjKlMnOpQrStUvWx";\n', encoding="utf-8"
    )
    findings = ClientSideSecretLiteralGuard().run(tmp_path, mkprofile(tmp_path, features={"frontend"}))
    assert len(findings) == 1
    assert "Slack" in findings[0].message


def test_client_side_secret_literal_fires_twilio_key(tmp_path: Path) -> None:
    # (eslint-plugin-no-secrets): Twilio API key, "SK" + 32 lowercase alnum
    (tmp_path / "sms.ts").write_text(
        'const t = "SKabcdef0123456789abcdef0123456789";\n', encoding="utf-8"
    )
    findings = ClientSideSecretLiteralGuard().run(tmp_path, mkprofile(tmp_path, features={"frontend"}))
    assert len(findings) == 1
    assert "Twilio" in findings[0].message


def test_client_side_secret_literal_silent_sk_uppercase_short(tmp_path: Path) -> None:
    # FP-bait: an "SK"-prefixed identifier too short to be a real Twilio key must not fire
    (tmp_path / "ui.ts").write_text('const SKU = "SKabc123";\n', encoding="utf-8")
    assert ClientSideSecretLiteralGuard().run(tmp_path, mkprofile(tmp_path, features={"frontend"})) == []


def test_client_side_secret_literal_fires_slack_webhook_url(tmp_path: Path) -> None:
    # a Slack incoming-webhook URL pasted into client code
    (tmp_path / "notify.js").write_text(
        'const url = "https://hooks.slack.com/services/T012ABCDEF/B012GHIJKL/abcdefghijklmnopqrstuvwx";\n',
        encoding="utf-8",
    )
    findings = ClientSideSecretLiteralGuard().run(tmp_path, mkprofile(tmp_path, features={"javascript"}))
    assert len(findings) == 1
    assert "Slack webhook" in findings[0].message


def test_client_side_secret_literal_fires_pinecone_key(tmp_path: Path) -> None:
    # (trufflehog cross-check)
    (tmp_path / "vec.ts").write_text(
        'const k = "pcsk_abcde_' + "f" * 63 + '";\n', encoding="utf-8"
    )
    findings = ClientSideSecretLiteralGuard().run(tmp_path, mkprofile(tmp_path, features={"frontend"}))
    assert len(findings) == 1
    assert "Pinecone" in findings[0].message


def test_client_side_secret_literal_fires_replicate_key(tmp_path: Path) -> None:
    # (trufflehog cross-check)
    (tmp_path / "replicate.js").write_text(
        'const k = "r8_' + "A" * 37 + '";\n', encoding="utf-8"
    )
    findings = ClientSideSecretLiteralGuard().run(tmp_path, mkprofile(tmp_path, features={"frontend"}))
    assert len(findings) == 1
    assert "Replicate" in findings[0].message


def test_client_side_secret_literal_fires_groq_key(tmp_path: Path) -> None:
    # (trufflehog cross-check)
    (tmp_path / "groq.ts").write_text(
        'const k = "gsk_' + "a" * 52 + '";\n', encoding="utf-8"
    )
    findings = ClientSideSecretLiteralGuard().run(tmp_path, mkprofile(tmp_path, features={"frontend"}))
    assert len(findings) == 1
    assert "Groq" in findings[0].message


def test_client_side_secret_literal_fires_langsmith_key(tmp_path: Path) -> None:
    # (trufflehog cross-check)
    (tmp_path / "langsmith.ts").write_text(
        'const k = "lsv2_sk_' + "a" * 32 + "_" + "b" * 10 + '";\n', encoding="utf-8"
    )
    findings = ClientSideSecretLiteralGuard().run(tmp_path, mkprofile(tmp_path, features={"frontend"}))
    assert len(findings) == 1
    assert "LangSmith" in findings[0].message


def test_client_side_secret_literal_fires_supabase_pat(tmp_path: Path) -> None:
    # (trufflehog cross-check) — distinct from the service-role/anon JWT keys this
    # project already covers elsewhere; a PAT authenticates the management API itself.
    (tmp_path / "supabase.ts").write_text(
        'const k = "sbp_' + "a" * 40 + '";\n', encoding="utf-8"
    )
    findings = ClientSideSecretLiteralGuard().run(tmp_path, mkprofile(tmp_path, features={"frontend"}))
    assert len(findings) == 1
    assert "Supabase" in findings[0].message


def test_client_side_secret_literal_silent_short_new_provider_prefixes(tmp_path: Path) -> None:
    # FP-bait: each of the 5 new provider prefixes, too short to be a real key, stays silent
    (tmp_path / "ui.ts").write_text(
        'const a = "pcsk_abcde_tooshort";\n'
        'const b = "r8_tooshort";\n'
        'const c = "gsk_tooshort";\n'
        'const d = "lsv2_pt_tooshort_short";\n'
        'const e = "sbp_tooshort";\n',
        encoding="utf-8",
    )
    assert ClientSideSecretLiteralGuard().run(tmp_path, mkprofile(tmp_path, features={"frontend"})) == []


def test_client_side_secret_literal_silent_new_provider_prefixes_one_char_short(tmp_path: Path) -> None:
    # FP-bait near-miss: each of the 5 new provider prefixes, exactly one character short of
    # its real required length, stays silent (not just "short" at ~8 chars — the real boundary).
    (tmp_path / "ui.ts").write_text(
        'const a = "pcsk_abcde_' + "f" * 62 + '";\n'        # Pinecone: 63 required, 62 given
        'const b = "r8_' + "A" * 36 + '";\n'                # Replicate: 37 required, 36 given
        'const c = "gsk_' + "a" * 51 + '";\n'                # Groq: 52 required, 51 given
        'const d = "lsv2_pt_' + "a" * 31 + "_" + "b" * 10 + '";\n'  # LangSmith: 32 required, 31 given
        'const e = "sbp_' + "a" * 39 + '";\n',              # Supabase: 40 required, 39 given
        encoding="utf-8",
    )
    assert ClientSideSecretLiteralGuard().run(tmp_path, mkprofile(tmp_path, features={"frontend"})) == []


def test_client_side_secret_literal_silent_other_slack_url(tmp_path: Path) -> None:
    # FP-bait: an ordinary slack.com URL that isn't the webhook shape must not fire
    (tmp_path / "link.ts").write_text(
        'const url = "https://slack.com/help/article/123";\n', encoding="utf-8"
    )
    assert ClientSideSecretLiteralGuard().run(tmp_path, mkprofile(tmp_path, features={"frontend"})) == []


def test_client_side_secret_literal_multi_provider_one_line(tmp_path: Path) -> None:
    # two distinct-provider secrets on one line both surface (finditer, distinct provider labels)
    (tmp_path / "cfg.ts").write_text(
        'const c = { a: "sk-proj-AAAAAAAAAAAAAAAAAAAA", b: "AKIAIOSFODNN7EXAMPLE" };\n',
        encoding="utf-8",
    )
    findings = ClientSideSecretLiteralGuard().run(tmp_path, mkprofile(tmp_path, features={"frontend"}))
    assert len(findings) == 2
    # `OpenAI` and `Anthropic` are separate labels now — collapsing them gave two distinct keys
    # one fingerprint (#488 review).
    providers = {"OpenAI", "AWS"}
    assert all(any(p in f.message for p in providers) for f in findings)


def test_client_side_secret_literal_silent_identifier_ending_in_prefix(tmp_path: Path) -> None:
    # `myAKIA...` is an identifier, not a token boundary — must not match
    (tmp_path / "x.ts").write_text("const myAKIAHelper = buildKey();\n", encoding="utf-8")
    assert ClientSideSecretLiteralGuard().run(tmp_path, mkprofile(tmp_path, features={"frontend"})) == []


def test_client_side_secret_literal_silent_in_comment(tmp_path: Path) -> None:
    (tmp_path / "note.js").write_text(
        '// example: sk-proj-FSAFCREDACTEDOVY7EfDDXIMrVayZub7TakA\n', encoding="utf-8"
    )
    assert ClientSideSecretLiteralGuard().run(tmp_path, mkprofile(tmp_path, features={"frontend"})) == []


def test_client_side_secret_literal_pragma_silences(tmp_path: Path) -> None:
    content = (
        'const h = "sk-proj-FSAFCREDACTEDOVY7EfDDXIMrVayZub7TakA";\n'
        "// security: allow-client-side-secret\n"
    )
    (tmp_path / "fixture.ts").write_text(content, encoding="utf-8")
    assert ClientSideSecretLiteralGuard().run(tmp_path, mkprofile(tmp_path, features={"frontend"})) == []


def test_client_side_secret_literal_downgrades_nonproduct_not_drops(tmp_path: Path) -> None:
    """a key literal under a test/fixture path is DOWNGRADED to `medium`, not dropped
    entirely — a real key accidentally committed to a fixture is still a live leak, and a silent
    skip cannot be told apart from "no key in this file". Non-vacuous: before this fix the guard
    used `continue` on `is_nonproduct_path` and this exact input produced zero findings; it must
    now produce exactly one, at reduced severity, mirroring the sibling public-browser-key
    "downgrade, not suppress" contract already in this guard (#488 B3) — but at a different target
    severity: `medium` (not `low`, PR #583 review), since `medium` is one of the three values the
    action's `fail-on` input (`action.yml`) accepts and `low` is not."""
    d = tmp_path / "tests"
    d.mkdir()
    (d / "api.spec.ts").write_text(
        'const h = "sk-proj-FSAFCREDACTEDOVY7EfDDXIMrVayZub7TakA";\n', encoding="utf-8"
    )
    findings = ClientSideSecretLiteralGuard().run(tmp_path, mkprofile(tmp_path, features={"frontend"}))
    assert len(findings) == 1
    assert findings[0].severity == "medium"
    assert findings[0].rule == "client-side-secret-literal/hardcoded-api-key-literal"
    assert "test/fixture/example path" in findings[0].message


def test_client_side_secret_literal_nonproduct_pragma_still_fully_suppresses(tmp_path: Path) -> None:
    """The downgrade above must not blunt the user's own opt-out: the pragma still silences the
    finding completely in a test path exactly as in a production one."""
    d = tmp_path / "tests"
    d.mkdir()
    content = (
        'const h = "sk-proj-FSAFCREDACTEDOVY7EfDDXIMrVayZub7TakA";\n'
        "// security: allow-client-side-secret\n"
    )
    (d / "api.spec.ts").write_text(content, encoding="utf-8")
    assert ClientSideSecretLiteralGuard().run(tmp_path, mkprofile(tmp_path, features={"frontend"})) == []


def test_client_side_secret_literal_applies_gate(tmp_path: Path) -> None:
    guard = ClientSideSecretLiteralGuard()
    assert guard.applies(mkprofile(tmp_path, features={"frontend"})) is True
    assert guard.applies(mkprofile(tmp_path, features={"javascript"})) is True
    # #1082: `.ts/.tsx` are in `_JS_SUFFIXES` but produce only the `typescript` feature, so the
    # gate must accept it or a TS-only repo is never scanned.
    assert guard.applies(mkprofile(tmp_path, features={"typescript"})) is True
    assert guard.applies(mkprofile(tmp_path, features={"express", "typescript"})) is True
    assert guard.applies(mkprofile(tmp_path, features={"python", "fastapi"})) is False
    assert guard.applies(mkprofile(tmp_path, features={"go"})) is False


# --- #488 review -------------------------------------------------------------------------------

def _secret_run(tmp_path: Path, src: str) -> list[Finding]:
    (tmp_path / "cfg.js").write_text(src, encoding="utf-8")
    profile = mkprofile(tmp_path, features={"frontend", "javascript"})
    return ClientSideSecretLiteralGuard().run(tmp_path, profile)


def test_firebase_web_config_key_does_not_fire_high(tmp_path: Path) -> None:
    # `AIza[0-9A-Za-z_-]{35}` is the exact shape of a Firebase web `apiKey`, which Google documents
    # as non-secret and REQUIRED in client code — access is controlled by Security Rules and key
    # restrictions, not secrecy. Every React+Firebase app got an unfixable HIGH in a CI gate,
    # remediated as "Rotate the exposed key immediately" (#488 review).
    #
    # UPDATED for the second-pass review (B3): the contract is now DOWNGRADE, not suppress. The
    # requirement this test exists for is unchanged and is asserted more precisely below — no HIGH,
    # so no unfixable CI gate — but the key is disclosed at `info` so the allowlist decision is
    # auditable rather than invisible.
    src = (
        "export const firebaseConfig = {\n"
        '  apiKey: "AIzaSyC1x9vQ8mR3nT7pL2kJ5hG4fD6sA0bZ8wX",\n'
        '  authDomain: "demo.firebaseapp.com",\n'
        '  messagingSenderId: "1234567890",\n'
        "};\n"
        "initializeApp(firebaseConfig);\n"
    )
    found = _secret_run(tmp_path, src)
    assert [f.severity for f in found] == ["info"]
    assert found[0].rule == "client-side-secret-literal/public-browser-key"


def test_google_maps_browser_key_does_not_fire_high(tmp_path: Path) -> None:
    # Same contract change as the Firebase case: disclosed at `info`, never HIGH (B3).
    src = (
        'import { Loader } from "@react-google-maps/api";\n'
        'const loader = new Loader({ apiKey: "AIzaSyB2y8wQ7nS4oU6qM3lK9hF5gE7tB1cA9xY", version: "weekly" });\n'
    )
    found = _secret_run(tmp_path, src)
    assert [f.severity for f in found] == ["info"]


def test_bare_google_api_key_still_fires(tmp_path: Path) -> None:
    # The allowlist is CONTEXT-SCOPED, not blanket: a Google API key with no Firebase/Maps wiring
    # nearby is a real leak — a server-side key pasted into client JS.
    src = (
        'const TRANSLATE_KEY = "AIzaSyD3z9xR6mT8pV1nQ4jL7kH2gF5sC0bA8wZ";\n'
        "fetch(endpoint + TRANSLATE_KEY);\n"
    )
    findings = _secret_run(tmp_path, src)
    assert len(findings) == 1
    assert "Google" in findings[0].message


def test_openai_and_anthropic_keys_are_distinct_findings(tmp_path: Path) -> None:
    # `_provider_label` mapped both `sk-proj-` and `sk-ant-` to one string, so two distinct leaked
    # keys on one line produced byte-identical messages at the same `file:lineno` — one fingerprint
    # for two secrets, so waiving one waived the other (#488 review).
    from agentsec.triage import fingerprint
    src = 'const a = "sk-proj-AAAAAAAAAAAAAAAAAAAAAAAA", b = "sk-ant-BBBBBBBBBBBBBBBBBBBBBBBB";\n'
    findings = _secret_run(tmp_path, src)
    assert len(findings) == 2
    assert len({fingerprint(f) for f in findings}) == 2, "two secrets collapsed into one fingerprint"
    messages = " ".join(f.message for f in findings)
    assert "OpenAI" in messages and "Anthropic" in messages


# --- #488 second-pass review (B3): the allowlist suppressed rather than downgraded ---------------

_FB_KEY = "AIzaSyA" + "b" * 34
_SRV_KEY = "AIzaSyZ" + "q" * 34


def _rules(tmp_path: Path) -> list[tuple[str, str]]:
    return [
        (f.severity, f.rule.rsplit("/", 1)[-1])
        for f in ClientSideSecretLiteralGuard().run(tmp_path, mkprofile(tmp_path, features={"frontend"}))
    ]


def test_unrelated_server_key_near_a_firebase_config_still_fires(tmp_path: Path) -> None:
    # THE B3 FALSE NEGATIVE. The allowlist was proximity-only over a +/- 6 line window, so a
    # genuinely unrelated Google SERVER key three lines below a legitimate Firebase config inherited
    # the exemption and the file produced ZERO findings.
    #
    # The fix is structural: the token must BE THE VALUE of an api-key-named binding, not merely sit
    # near the wiring. `gcpServerKey = "AIza…"` is not, so it is reported.
    (tmp_path / "a.js").write_text(
        "const firebaseConfig = {\n"
        f'  apiKey: "{_FB_KEY}",\n'
        '  authDomain: "demo.firebaseapp.com",\n'
        '  projectId: "demo",\n'
        "};\n"
        f'const gcpServerKey = "{_SRV_KEY}";\n',
        encoding="utf-8",
    )
    got = _rules(tmp_path)
    assert ("high", "google-key-not-public") in got, "the unrelated server key must still fire"
    assert ("info", "public-browser-key") in got, "the Firebase key is disclosed, not dropped"


def test_firebase_config_alone_is_info_not_high(tmp_path: Path) -> None:
    # The other direction (F4/rule 1): the allowlist exists because Google documents a Firebase web
    # `apiKey` as non-secret and REQUIRED in client code, so firing HIGH with "rotate immediately"
    # was an unfixable CI finding. It must still not produce a HIGH.
    (tmp_path / "a.js").write_text(
        f'const cfg = {{ apiKey: "{_FB_KEY}", authDomain: "d.firebaseapp.com", projectId: "d" }};\n',
        encoding="utf-8",
    )
    got = _rules(tmp_path)
    assert got == [("info", "public-browser-key")]
    assert not any(sev == "high" for sev, _ in got)


def test_maps_browser_key_is_info(tmp_path: Path) -> None:
    (tmp_path / "a.js").write_text(
        f'const googleMapsApiKey = "{_FB_KEY}";\n'
        'import { useJsApiLoader } from "@react-google-maps/api";\n',
        encoding="utf-8",
    )
    assert _rules(tmp_path) == [("info", "public-browser-key")]


def test_bare_aiza_key_with_no_wiring_still_fires_high(tmp_path: Path) -> None:
    # Unchanged: a server-side Google API key pasted into client JS with no Firebase/Maps wiring is
    # a real leak and stays HIGH. It carries the GOOGLE-specific rule id (#488 re-gate, F3) — the
    # severity and the message are unchanged, only the rule name distinguishes it, so the canary can
    # see the allowlist widening.
    (tmp_path / "a.js").write_text(f'const k = "{_SRV_KEY}";\n', encoding="utf-8")
    assert _rules(tmp_path) == [("high", "google-key-not-public")]


# --- #488 agentic gate (B3 refix / B35): the allowlist failed BOTH ways ------------------------

_AIZA = "AIza" + ("S9xKEYab" * 5)[:35]


def test_generic_apikey_name_near_a_topical_word_still_fires_high(tmp_path: Path) -> None:
    # THE FAIL-OPEN. `apiKey` is also what a developer calls a genuinely secret Google key, and
    # `geocod`/`places` nearby is no evidence about the key at all. That combination downgraded an
    # unrestricted SERVER key to `info`, below the `--fail-on high` gate.
    #
    # The topical word MUST live in CODE, not in a `//` comment. `run()` calls `strip_js_comments()`
    # and builds the context window from the STRIPPED text, so a word in a comment can never reach
    # the window at any revision — the original version of this test therefore passed at the very
    # commit it was written to pin, and pinned nothing (#488 independent gate, H3).
    #
    # Scope of what THIS replacement pins, stated precisely because the first version overclaimed
    # (#488 re-gate, F8): it is a real guard-level regression test for the `cd2ea4b9` → `87bbcaf5`
    # change, and it fails at `cd2ea4b9`. It also PASSES at `87bbcaf5`, so it does not pin anything
    # the `6ee79a82` commit itself changed — that commit's pins are the F1-F7 tests below.
    src = (
        'const mode = "geocoding";\n'
        f'const apiKey = "{_AIZA}";\n'
        "sendToAnalyticsBackend(apiKey);\n"
    )
    found = _secret_run(tmp_path, src)
    assert [f.severity for f in found] == ["high"]


def test_maps_script_url_key_is_info_not_high(tmp_path: Path) -> None:
    # THE FAIL-CLOSED. Google's own documented Maps spelling is a `?key=` query parameter on the
    # script URL, not a named binding, so requiring a binding made a legitimate BROWSER key fire HIGH
    # with "rotate immediately" — the unfixable-CI-finding class the allowlist exists to prevent.
    src = (
        'const s = document.createElement("script");\n'
        f's.src = "https://maps.googleapis.com/maps/api/js?key={_AIZA}&libraries=places";\n'
    )
    found = _secret_run(tmp_path, src)
    assert [f.severity for f in found] == ["info"]


def test_generic_apikey_with_a_structural_marker_is_info(tmp_path: Path) -> None:
    # The generic name IS acceptable with structural corroboration: a Firebase config sibling, or a
    # strong Google-client marker (an import, a loader call, the API host). Not a topical word.
    for src in (
        f'const cfg = {{ apiKey: "{_AIZA}", authDomain: "d.firebaseapp.com", projectId: "d" }};\n',
        f'import {{ Loader }} from "@react-google-maps/api";\nconst l = new Loader({{ apiKey: "{_AIZA}" }});\n',
    ):
        found = _secret_run(tmp_path, src)
        assert [f.severity for f in found] == ["info"], src


def test_two_same_provider_keys_on_one_line_are_distinct_findings(tmp_path: Path) -> None:
    # B35. The fix varied the message by PROVIDER, not by match, so two keys from the same provider on
    # one line were byte-identical in rule/location/message and shared a fingerprint. `exceptions.py`
    # matches on fingerprint, so waiving one — say the stale half of a rotation — silently waived the
    # other, still-live secret.
    src = 'const a = "sk-proj-' + "A" * 24 + '", b = "sk-proj-' + "B" * 24 + '";\n'
    found = _secret_run(tmp_path, src)
    assert len(found) == 2
    assert len({f.fingerprint() for f in found}) == 2, "same-provider keys must not collapse"


# --- #488 independent adversarial gate: the allowlist may only spare what IDENTIFIES the key -----
#
# THE INVARIANT, one line: an `AIza…` token may be downgraded to `info` only when something actually
# IDENTIFIES it as Google's documented public browser key — a host+path, a name that asserts which
# SIDE it lives on, or the token's own enclosing structure. NEVER a topical word, an import, or a
# neighbouring statement in a line window: an allowlist that reads the neighbourhood spares the
# neighbourhood, not the identifier. The tests below are the traded-against half of the widening —
# every one of them fails at the pre-fix tip (87bbcaf5).

_AIZA2 = "AIza" + ("Q7zPQRcd" * 5)[:35]


def test_non_google_url_with_a_key_param_still_fires_high(tmp_path: Path) -> None:
    # H1. `_MAPS_URL_KEY` was `[?&]key=$` — it checked NOTHING about the URL, so any query parameter
    # literally named `key`, on any host, was read as Google's Maps script URL. Inside a Firebase
    # file (weak context anywhere in the ±6-line window) that downgraded a real server key to `info`.
    src = (
        'import { initializeApp } from "firebase/app";\n'
        f'const u = "https://billing.internal.example.com/admin?key={_AIZA}";\n'
    )
    assert [f.severity for f in _secret_run(tmp_path, src)] == ["high"]


def test_geocoding_web_service_key_still_fires_high(tmp_path: Path) -> None:
    # H1, the sharpest case: Google's own Geocoding **Web Service**, which Google documents as
    # server-side and IP-restricted. A key for it pasted into client JS is a textbook leak, and the
    # bare `[?&]key=$` handed it back as "a PUBLIC project identifier rather than a secret".
    src = f'const u = "https://maps.googleapis.com/maps/api/geocode/json?address=NYC&key={_AIZA}";\n'
    assert [f.severity for f in _secret_run(tmp_path, src)] == ["high"]


def test_maps_js_path_as_a_query_value_still_fires_high(tmp_path: Path) -> None:
    # H1, adversarial: the Maps JS path appearing as a query VALUE of a different host is not the
    # Maps JS endpoint. The host must be the URL's authority (`//maps.googleapis.com/...`).
    src = f'const u = "https://evil.example.com/p?x=maps.googleapis.com/maps/api/js&key={_AIZA}";\n'
    assert [f.severity for f in _secret_run(tmp_path, src)] == ["high"]


def test_server_key_below_a_firebase_config_is_not_blanketed(tmp_path: Path) -> None:
    # H2. The generic `apiKey` name was corroborated from a ±6-line window, so a legitimate Firebase
    # config object a few lines up vouched for an unrelated top-level `const apiKey = …`. Corroboration
    # is now scoped to the token's own enclosing expression: the config object is `info`, the
    # top-level binding — which no structure vouches for — is `high`.
    src = (
        f'const firebaseConfig = {{ apiKey: "{_AIZA2}", authDomain: "d", projectId: "p" }};\n'
        f'const apiKey = "{_AIZA}";\n'
    )
    assert sorted(f.severity for f in _secret_run(tmp_path, src)) == ["high", "info"]


def test_server_key_below_a_lone_firebase_import_still_fires_high(tmp_path: Path) -> None:
    # H2. A file-level import is the most realistic blanket of all — every Firebase app has one, and
    # it corroborated every generic `apiKey` within six lines of it.
    src = (
        'import { initializeApp } from "firebase/app";\n'
        "const x = 1;\nconst y = 2;\n"
        f'const apiKey = "{_AIZA}";\n'
    )
    assert [f.severity for f in _secret_run(tmp_path, src)] == ["high"]


def test_clerk_getauth_does_not_corroborate_a_google_key(tmp_path: Path) -> None:
    # H2, the case the tip made WORSE: `getAuth\s*\(` was accepted as strong Google evidence, but
    # `getAuth(req)` is Clerk's and NextAuth's spelling at least as often as Firebase's. A Clerk call
    # next to a Google server key measured `high` at the parent and `info` at the tip.
    src = (
        'import { getAuth } from "@clerk/nextjs/server";\n'
        "const session = getAuth(req);\n"
        f'const apiKey = "{_AIZA}";\n'
    )
    assert [f.severity for f in _secret_run(tmp_path, src)] == ["high"]


def test_screaming_snake_maps_key_on_a_topical_word_alone_fires_high(tmp_path: Path) -> None:
    # H7. `GOOGLE_MAPS_API_KEY` names the PRODUCT but not the SIDE — without a bundler-public prefix
    # it is equally the conventional name for a server-side Geocoding / Places-Web-Service key. A
    # topical word (`places`) is not evidence about the key, so it now needs structural wiring.
    src = f'const mode = "places";\nconst GOOGLE_MAPS_API_KEY = "{_AIZA}";\n'
    assert [f.severity for f in _secret_run(tmp_path, src)] == ["high"]


def test_two_public_browser_keys_on_one_line_are_distinct_findings(tmp_path: Path) -> None:
    # H5. The B35 column fix was applied only to the HIGH path; `_public_key_finding` still emitted a
    # bare `file:lineno` with a CONSTANT message, so two allowlisted keys on one line were identical
    # in rule + location + message and shared one fingerprint. `exceptions.py` matches on fingerprint,
    # so waiving one waived the other — on precisely the findings whose triage judgement is a call.
    src = f'const c = {{ apiKey: "{_AIZA}", authDomain: "x", googleMapsApiKey: "{_AIZA2}" }};\n'
    found = _secret_run(tmp_path, src)
    assert [f.severity for f in found] == ["info", "info"]
    assert len({f.fingerprint() for f in found}) == 2, "two allowlisted keys collapsed to one id"
    assert [f.location.rsplit(":", 1)[-1] for f in found] == ["22", "100"]


# --- ... and the direction it trades against: real browser keys must STAY `info` -----------------
# These are preserved-behaviour tests (they pass at the tip too). The obvious fix for either
# direction of this guard worsens the other — that is this branch's documented history — so the
# narrowing above is pinned against the widest set of genuinely-public shapes we could construct.


def test_maps_script_url_shapes_stay_info(tmp_path: Path) -> None:
    for src in (
        f'const s = "https://maps.googleapis.com/maps/api/js?key={_AIZA}";\n',
        f'const s = "https://maps.googleapis.com/maps/api/js?key={_AIZA}&libraries=places";\n',
        f'const s = "https://maps.googleapis.com/maps/api/js?libraries=places&callback=init&key={_AIZA}";\n',
        f'const s = "//maps.googleapis.com/maps/api/js?key={_AIZA}";\n',          # protocol-relative
        f'<script src={{"https://maps.googleapis.com/maps/api/js?key={_AIZA}"}} />;\n',   # JSX
    ):
        assert [f.severity for f in _secret_run(tmp_path, src)] == ["info"], src


def test_real_firebase_and_maps_wiring_stays_info(tmp_path: Path) -> None:
    for src in (
        # the field order must not matter — `apiKey` last, siblings before it
        f'const c = {{ authDomain: "d.firebaseapp.com", projectId: "d", apiKey: "{_AIZA}" }};\n',
        # the config nested under a key of a bigger `environment` object (Angular/Vue shape)
        "const environment = {\n  production: false,\n  firebase: {\n"
        f'    apiKey: "{_AIZA}",\n    authDomain: "d.firebaseapp.com",\n' "  },\n};\n",
        # the object literal passed straight into the loader, no siblings at all — the CALLEE is the
        # corroboration, which is why the scope reaches two bracket levels out
        "initializeApp({\n" f'  apiKey: "{_AIZA}",\n' "});\n",
        f'const l = new Loader({{ apiKey: "{_AIZA}", version: "weekly" }});\n',
        f'const {{ isLoaded }} = useJsApiLoader({{ googleMapsApiKey: "{_AIZA}" }});\n',
        # a function-scoped Firebase config
        "export function boot() {\n"
        f'  return initializeApp({{ apiKey: "{_AIZA}", projectId: "d" }});\n' "}\n",
    ):
        assert [f.severity for f in _secret_run(tmp_path, src)] == ["info"], src


def test_enclosing_expression_is_total(tmp_path: Path) -> None:
    # The scope walker indexes into a joined buffer, so an out-of-range line index or column ran off
    # the end and raised `IndexError` — found by attacking the fix, not by any fixture reaching it
    # through `run()`. A guard helper that can raise turns one odd file into a lost audit, so the
    # contract is clamped and asserted directly. The bracket walk is also bounded, which fails CLOSED.
    from agentsec.guards.client_side_secret_literal import _enclosing_expression
    for lines, index, col in (([], 0, 0), (["x"], 9, 0), (["x"], 0, 99), (["}", "{"], 1, 0)):
        text = "\n".join(lines)
        pos = sum(len(x) + 1 for x in lines[:index]) + col
        assert isinstance(_enclosing_expression(text, text, pos), str)
    # ... and degenerate/unbalanced source must still be scanned, and stay fail-closed
    for src in (
        '});\nconst apiKey = "' + _AIZA + '";\n',
        '({\nconst apiKey = "' + _AIZA + '";\n',
        'const apiKey = "' + _AIZA + '\n',                       # unterminated string
    ):
        assert [f.severity for f in _secret_run(tmp_path, src)] == ["high"], src


def test_screaming_snake_maps_key_with_real_maps_wiring_stays_info(tmp_path: Path) -> None:
    # The H7 trade: narrowing `GOOGLE_MAPS_API_KEY` to structural evidence must not break the Maps
    # app that actually has the wiring — that is the unfixable-CI-finding class the allowlist exists
    # for. A bundler-public name (`NEXT_PUBLIC_…`) asserts the side by itself and is unaffected.
    for src in (
        f'import {{ useJsApiLoader }} from "@react-google-maps/api";\nconst GOOGLE_MAPS_API_KEY = "{_AIZA}";\n',
        f'const NEXT_PUBLIC_FIREBASE_API_KEY = "{_AIZA}";\nconst p = "firebase";\n',
        f'const googleMapsApiKey = "{_AIZA}";\nimport {{ useJsApiLoader }} from "@react-google-maps/api";\n',
    ):
        assert [f.severity for f in _secret_run(tmp_path, src)] == ["info"], src


def test_bundler_public_prefix_is_a_rule_not_an_enumeration(tmp_path: Path) -> None:
    # #488 re-gate F1. The browser-explicit check was an enumeration of exact names, so
    # `NEXT_PUBLIC_GOOGLE_MAPS_API_KEY` was public but the Vite and CRA spellings of the SAME key
    # fell through to the ambiguous branch and fired HIGH — an unfixable CI finding in any Vite or
    # CRA Maps app. All bundler-public prefixes assert the side; the bundler must not decide it.
    for name in (
        "VITE_GOOGLE_MAPS_API_KEY",
        "REACT_APP_GOOGLE_MAPS_API_KEY",
        "NEXT_PUBLIC_GOOGLE_MAPS_API_KEY",
        "GATSBY_GOOGLE_MAPS_API_KEY",
        "EXPO_PUBLIC_GOOGLE_MAPS_API_KEY",
    ):
        src = f'const mode = "places";\nconst {name} = "{_AIZA}";\n'
        assert [f.severity for f in _secret_run(tmp_path, src)] == ["info"], name
    # FP-bait: the UNPREFIXED name is equally a server-side Geocoding key and must stay ambiguous —
    # a topical word alone must not spare it (the H7 trade this guard already made).
    bare = f'const mode = "places";\nconst GOOGLE_MAPS_API_KEY = "{_AIZA}";\n'
    assert [f.severity for f in _secret_run(tmp_path, bare)] == ["high"]


def test_same_line_neighbouring_statement_does_not_corroborate(tmp_path: Path) -> None:
    # #488 re-gate F4. The top-level fallback returned the token's whole LINE, so a config object
    # sharing the line vouched for an unrelated `apiKey` — H2's failure mode at line granularity.
    src = f'const cfg = {{ authDomain: "d", projectId: "p" }}; const apiKey = "{_AIZA}";\n'
    assert [f.severity for f in _secret_run(tmp_path, src)] == ["high"], src
    # The traded-against direction: a REAL config object must still be spared.
    ok = f'const firebaseConfig = {{\n  apiKey: "{_AIZA}",\n  authDomain: "x.firebaseapp.com",\n}};\n'
    assert [f.severity for f in _secret_run(tmp_path, ok)] == ["info"], ok


def test_scope_budget_exhaustion_fails_closed(tmp_path: Path) -> None:
    # #488 re-gate F2. The comment claimed hitting `_MAX_SCOPE_CHARS` yields LESS scope and so fails
    # CLOSED. It did not: aborting the walk fell back to the whole line, which could be WIDER than
    # the bracket scope, so the bound could turn a HIGH into an INFO. The corroborator here sits
    # after the closer on the token's own line and must not be reachable.
    pad = "".join(f"  x{i}: 1,\n" for i in range(600))
    src = f'foo({{\n{pad}  apiKey: "{_AIZA}"}}); const authDomain = "d";\n'
    assert [f.severity for f in _secret_run(tmp_path, src)] == ["high"], "bound must fail closed"


def test_maps_url_host_is_case_insensitive(tmp_path: Path) -> None:
    # #488 re-gate F6. URL scheme/host are case-insensitive (RFC 3986 §3.2.2); this was the guard's
    # only case-sensitive regex, so an upper-cased host regressed the documented public key to HIGH.
    for host in ("maps.googleapis.com", "MAPS.GOOGLEAPIS.COM", "Maps.GoogleAPIs.com"):
        src = f'const s = "https://{host}/maps/api/js?key={_AIZA}";\n'
        assert [f.severity for f in _secret_run(tmp_path, src)] == ["info"], host
    # FP-bait: the Geocoding WEB SERVICE endpoint is a server key and must still fire (H1's class).
    bad = f'const s = "https://maps.googleapis.com/maps/api/geocode/json?key={_AIZA}";\n'
    assert [f.severity for f in _secret_run(tmp_path, bad)] == ["high"], bad


def test_enclosing_expression_clamps_negative_index() -> None:
    # #488 re-gate F7. The docstring promised an out-of-range index/col is clamped; a NEGATIVE index
    # raised IndexError. Unreachable from run() (lineno-1 and m.start() are both >= 0), but the
    # contract as written was false, and the totality test only probed non-negative inputs.
    from agentsec.guards.client_side_secret_literal import _enclosing_expression

    for pos in (-5, -1, 0, 3, 999):
        assert isinstance(_enclosing_expression("", "", pos), str)
        assert isinstance(_enclosing_expression("const a = 1;", "const a = 1;", pos), str)


def test_canary_catches_allowlist_widening_and_narrowing(tmp_path: Path) -> None:
    # #488 re-gate F3. The design doc claims `doctor --canary` sees BOTH directions. It did not:
    # `canary.compare()` asks whether each expected rule fires ANYWHERE, so the non-Google `sk-proj-`
    # plant kept `hardcoded-api-key-literal` alive however far the AIza allowlist widened. Adding a
    # third plant alone did NOT fix it (measured) — the distinct `google-key-not-public` rule is what
    # does, because only AIza tokens can produce it.
    from agentsec.canary import EXPECTED_RULES, write_canary_repo
    from agentsec.detect import detect
    from agentsec.guards import client_side_secret_literal as mod

    write_canary_repo(tmp_path)
    profile = detect(tmp_path)
    expected = EXPECTED_RULES["client-side-secret-literal"]

    def fired() -> set[str]:
        return {f.rule for f in mod.ClientSideSecretLiteralGuard().run(tmp_path, profile)}

    assert not (expected - fired()), "baseline: every expected rule must fire"

    original = mod._is_public_browser_key
    try:
        # Max WIDENING, faithfully scoped to the allowlist's own domain: spare every `AIza` token.
        # A blanket lambda would also spare `sk-proj-`, which the allowlist never touches, and would
        # make this test pass for the wrong reason.
        mod._is_public_browser_key = lambda token, *a, **k: token.startswith("AIza")  # type: ignore[assignment]
        assert "client-side-secret-literal/google-key-not-public" in expected - fired(), (
            "a WIDENED allowlist must kill an expected rule, or the canary cannot see a guard that "
            "starts downgrading every Google key"
        )
        # Max NARROWING: spare nothing.
        mod._is_public_browser_key = lambda *a, **k: False  # type: ignore[assignment]
        assert "client-side-secret-literal/public-browser-key" in expected - fired(), (
            "a NARROWED allowlist must kill an expected rule"
        )
    finally:
        mod._is_public_browser_key = original  # type: ignore[assignment]


def test_brace_inside_a_string_does_not_widen_the_scope(tmp_path: Path) -> None:
    # #488 fixup gate C1. The scope walks counted `{}()[]` inside STRING CONTENT as structure, and
    # the `;`/newline statement boundary is gated on depth == 0 — so one unbalanced `"}"` in a
    # comma-declarator left the walk at depth 1, disabled the boundary, and let the scope run up the
    # file. A real server key was spared because a config object several lines above came into scope.
    # Worse than the whole-line fallback it replaced, in the commit written to narrow it.
    src = (
        "export const firebaseConfig = {\n"
        '  apiKeyPub: "AIzaSyPUBLIC0123456789abcdefghijklmno",\n'
        '  authDomain: "demo.firebaseapp.com",\n'
        "};\n"
        f'const closeTpl = "}}", apiKey = "{_SRV_KEY}";\n'
    )
    got = [(f.severity, f.rule.rsplit("/", 1)[-1]) for f in _secret_run(tmp_path, src)]
    assert ("high", "google-key-not-public") in got, f"C1 fail-open — server key spared: {got}"
    # and the control: the identical file WITHOUT the stray brace behaves the same way
    clean = src.replace('const closeTpl = "}", apiKey', "const apiKey")
    got_clean = [(f.severity, f.rule.rsplit("/", 1)[-1]) for f in _secret_run(tmp_path, clean)]
    assert ("high", "google-key-not-public") in got_clean, got_clean
    # The traded-against direction is unaffected: a key genuinely inside the config is still spared.
    ok = (
        "export const firebaseConfig = {\n"
        f'  apiKey: "{_SRV_KEY}",\n'
        '  authDomain: "demo.firebaseapp.com",\n'
        "};\n"
    )
    assert [f.severity for f in _secret_run(tmp_path, ok)] == ["info"], ok


def test_statement_slice_is_total_on_degenerate_source() -> None:
    # #488 fixup gate L1. Prove the totality claim rather than asserting it.
    from agentsec.guards.base import strip_js_comments
    from agentsec.guards.client_side_secret_literal import _statement_slice

    for src in ("", "const a = 1;", 'const t = "}";', "({[", ")}]", 'const s = "unterminated\n',
                "`a${b}c`", "const rx = /\"/, y = 1;", "const t = `never closed"):
        struct = strip_js_comments(src, strip_strings=True)
        for pos in (-5, 0, len(src) // 2, len(src), len(src) + 9):
            assert isinstance(_statement_slice(struct, src, pos), str)


def test_lexical_constructs_cannot_widen_the_scope(tmp_path: Path) -> None:
    # #488 re-gate C1/C2. Three rounds of hand-rolled lexing each reopened the same fail-open on the
    # next unmodelled JavaScript construct: a brace inside a string, then a quote inside a `/.../`
    # regex, then an unterminated backtick that masked to EOF. The guard no longer carries a scanner
    # — structure comes from `strip_js_comments(..., strip_strings=True)`, which already models both.
    # Each case below spared a REAL server key at some point in that sequence.
    cases = {
        "brace in a string": (
            "export const firebaseConfig = {\n"
            '  apiKeyPub: "AIzaSyPUBLIC0123456789abcdefghijklmno",\n'
            '  authDomain: "demo.firebaseapp.com",\n'
            "};\n"
            f'const closeTpl = "}}", apiKey = "{_SRV_KEY}";\n'
        ),
        "quote inside a regex literal": (
            f'const rx = /"/, y = "authDomain"; const apiKey = "{_SRV_KEY}";\n'
        ),
        "unterminated template literal": (
            "const t = `oops;\n"
            "export const firebaseConfig = {\n"
            '  authDomain: "demo.firebaseapp.com",\n'
            "};\n"
            f'const apiKey = "{_SRV_KEY}";\n'
        ),
    }
    for name, src in cases.items():
        got = [(f.severity, f.rule.rsplit("/", 1)[-1]) for f in _secret_run(tmp_path, src)]
        assert ("high", "google-key-not-public") in got, f"{name}: server key spared -> {got}"


def test_quoted_object_keys_still_corroborate(tmp_path: Path) -> None:
    # The trade the structure/content split exists for. `_FIREBASE_SIBLING` matches object KEY names,
    # and `{ "authDomain": ... }` with QUOTED keys is ordinary JavaScript. Boundaries are found in the
    # blanked view, but the slice is taken from the REAL source — reading the blanked view here would
    # stop legitimate Firebase configs vouching for their own key and fire HIGH on every one of them,
    # which is the unfixable-CI-finding class this guard exists to avoid.
    src = (
        "export const firebaseConfig = {\n"
        f'  "apiKey": "{_SRV_KEY}",\n'
        '  "authDomain": "demo.firebaseapp.com",\n'
        "};\n"
    )
    assert [f.severity for f in _secret_run(tmp_path, src)] == ["info"], src


def test_bundler_public_prefix_residual_a_prefixed_secret_is_spared(tmp_path: Path) -> None:
    # #488 fixup gate M1. Documenting a real RESIDUAL, not asserting desired behaviour: the prefix
    # rule asserts which SIDE the value ships on, which is not the same as asserting it is harmless.
    # A developer who prefixes a genuinely secret key with a bundler-public prefix has leaked it into
    # the bundle AND told this guard to treat it as public. The prefix cannot distinguish the two, so
    # this is inherent to the F1 design; pinned so a future change to it is a deliberate one.
    src = f'const mode = "places";\nconst VITE_SECRET_API_KEY = "{_SRV_KEY}";\n'
    assert [f.severity for f in _secret_run(tmp_path, src)] == ["info"], (
        "known residual: a bundler-public prefix on a secret key is spared"
    )


def test_canary_plant_catches_the_widening_mechanisms(tmp_path: Path) -> None:
    # #488 fixup gate C2. The design doc claimed a mutation table that did not execute: the plant's
    # binding was `gcpServerKey`, which matches none of the four shapes the allowlist tests, so it was
    # HIGH unconditionally and NO regex change could move it. It caught only a total bypass of the
    # function — not a regression anyone would ship. The plant now binds the GENERIC `apiKey` with a
    # config object as out-of-scope bait, so the real mechanisms are covered.
    #
    # Each mutation patches the NAMED constant it claims to change. Patching the whole function
    # instead is precisely the error that produced the false table.
    import re as _re

    from agentsec.canary import EXPECTED_RULES, write_canary_repo
    from agentsec.detect import detect
    from agentsec.guards import client_side_secret_literal as mod

    write_canary_repo(tmp_path)
    profile = detect(tmp_path)
    expected = EXPECTED_RULES["client-side-secret-literal"]

    def missing() -> set[str]:
        return expected - {f.rule for f in mod.ClientSideSecretLiteralGuard().run(tmp_path, profile)}

    assert not missing(), "baseline: every expected rule must fire"

    _orig_strip = mod.strip_js_comments
    saved = (mod._enclosing_expression, mod.strip_js_comments, mod._FIREBASE_SIBLING,
             mod._is_public_browser_key)
    try:
        # H2: the scope unit reverts to a line window — the config above vouches for the key below.
        mod._enclosing_expression = lambda struct, text, pos: text[max(0, pos - 300): pos + 300]  # type: ignore[assignment]
        assert missing(), "H2 (line-window scope) must be caught"
        mod._enclosing_expression = saved[0]  # type: ignore[assignment]

        # C1: the structure view stops blanking string content — the plant's `"}"` re-opens the walk.
        mod.strip_js_comments = lambda s, **kw: _orig_strip(s)  # type: ignore[assignment]
        assert missing(), "C1 (string-blind walk) must be caught"
        mod.strip_js_comments = saved[1]  # type: ignore[assignment]

        # A widened corroboration regex.
        mod._FIREBASE_SIBLING = _re.compile(r"")  # type: ignore[assignment]
        assert missing(), "a sibling regex matching everything must be caught"
        mod._FIREBASE_SIBLING = saved[2]  # type: ignore[assignment]

        # Both extremes of the allowlist itself.
        mod._is_public_browser_key = lambda tok, *a, **k: tok.startswith("AIza")  # type: ignore[assignment]
        assert "client-side-secret-literal/google-key-not-public" in missing(), "max widening"
        mod._is_public_browser_key = lambda *a, **k: False  # type: ignore[assignment]
        assert "client-side-secret-literal/public-browser-key" in missing(), "max narrowing"
    finally:
        (mod._enclosing_expression, mod.strip_js_comments, mod._FIREBASE_SIBLING,
         mod._is_public_browser_key) = saved  # type: ignore[assignment]


def test_canary_gap_maps_url_widening_is_not_covered(tmp_path: Path) -> None:
    # The honest other half of the table above. A token in a `?key=` URL never reaches the generic
    # path, so the single high plant cannot see `_MAPS_URL_KEY` widening (H1's own class). Covering it
    # would need a second rule id. Pinned as a KNOWN GAP so it is a recorded decision rather than an
    # assumption — and so this test fails, loudly, if someone later closes it and forgets the doc.
    import re as _re

    from agentsec.canary import EXPECTED_RULES, write_canary_repo
    from agentsec.detect import detect
    from agentsec.guards import client_side_secret_literal as mod

    write_canary_repo(tmp_path)
    profile = detect(tmp_path)
    expected = EXPECTED_RULES["client-side-secret-literal"]
    saved = mod._MAPS_URL_KEY
    try:
        mod._MAPS_URL_KEY = _re.compile(r"[?&]key=$")  # H1, verbatim
        still_alive = not (expected - {f.rule for f in mod.ClientSideSecretLiteralGuard().run(tmp_path, profile)})
        assert still_alive, (
            "the H1 gap has been CLOSED — good, but wiki/guards/client-side-secret-"
            "literal.md still records it as an accepted gap. Update the doc and delete this test."
        )
    finally:
        mod._MAPS_URL_KEY = saved


# --- #1082: a TS-only repo (no `.js`, no react/vite) is in scope ------------------------------
# `detect.py` sets `typescript` for `.ts/.tsx` and `javascript` only for `.js/.jsx`, so before the
# fix a TS backend's key passed `--guards-only` unless some unrelated `.js` file switched the gate on.

_TS_ONLY = frozenset({"typescript"})
_OLD_MESSAGE_OPENAI = (
    "A hardcoded OpenAI API key / secret is in client-side JavaScript. "
    "Everything in the client bundle ships to every visitor, so the key is "
    "public the moment the app is served — anyone can read it in devtools "
    "and spend or pivot with it."
)


def _ts_run(tmp_path: Path, rel_path: str, src: str, features: frozenset[str] = _TS_ONLY) -> list[Finding]:
    f = tmp_path / rel_path
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_text(src, encoding="utf-8")
    profile = mkprofile(tmp_path, features=set(features))
    guard = ClientSideSecretLiteralGuard()
    assert guard.applies(profile) is True
    return guard.run(tmp_path, profile)


def test_issue_1082_ts_backend_key_fires_high(tmp_path: Path) -> None:
    findings = _ts_run(
        tmp_path,
        "src/server.ts",
        'const apiKey = "sk-proj-abcdefghijklmnop1234567890";\n',
        frozenset({"express", "typescript"}),
    )
    assert [(f.rule, f.severity, f.location.replace("\\", "/")) for f in findings] == [
        ("client-side-secret-literal/hardcoded-api-key-literal", "high", "src/server.ts:1:17")
    ]


def test_issue_1082_ts_mcp_positional_anthropic_key_fires_high(tmp_path: Path) -> None:
    # The line `mcp-hardcoded-credential` cannot see: a non-credential variable name.
    findings = _ts_run(
        tmp_path,
        "src/server.ts",
        'const anth = "sk-ant-api03-abcdefghijklmnop1234567890";\n',
        frozenset({"mcp", "typescript"}),
    )
    assert len(findings) == 1
    assert findings[0].severity == "high"
    assert "Anthropic" in findings[0].message


def test_issue_1082_ts_only_firebase_config_stays_info(tmp_path: Path) -> None:
    # FP-bait for the widening: an Angular-style `environment.ts` Firebase web config is a PUBLIC
    # identifier, so the allowlist must still downgrade it in a TS-only repo.
    src = (
        "export const environment = {\n"
        "  production: true,\n"
        "  firebase: {\n"
        '    apiKey: "AIzaSyC1x9vQ8mR3nT7pL2kJ5hG4fD6sA0bZ8wX",\n'
        '    authDomain: "demo.firebaseapp.com",\n'
        '    projectId: "demo",\n'
        "  },\n"
        "};\n"
    )
    findings = _ts_run(tmp_path, "src/environments/environment.ts", src)
    assert [(f.rule, f.severity) for f in findings] == [
        ("client-side-secret-literal/public-browser-key", "info")
    ]


def test_issue_1082_ts_only_comment_and_env_read_stay_silent(tmp_path: Path) -> None:
    src = (
        '// e.g. const k = "sk-proj-abcdefghijklmnop1234567890";\n'
        "/* sk-ant-api03-abcdefghijklmnop1234567890 */\n"
        "const apiKey = process.env.OPENAI_API_KEY;\n"
    )
    assert _ts_run(tmp_path, "src/server.ts", src) == []


def test_issue_1082_ts_only_pragma_silences_but_a_quoted_pragma_does_not(tmp_path: Path) -> None:
    key = 'const apiKey = "sk-proj-abcdefghijklmnop1234567890";\n'
    assert _ts_run(tmp_path, "src/a.ts", key + "// security: allow-client-side-secret\n") == []
    quoted = _ts_run(tmp_path, "src/b.ts", key + 'const note = "security: allow-client-side-secret";\n')
    assert [f.location.replace("\\", "/") for f in quoted] == ["src/b.ts:1:17"]


def test_issue_1082_ts_only_nonproduct_path_is_downgraded_not_dropped(tmp_path: Path) -> None:
    findings = _ts_run(tmp_path, "tests/api.spec.ts", 'const k = "sk-proj-abcdefghijklmnop1234567890";\n')
    assert [f.severity for f in findings] == ["medium"]


def test_issue_1082_message_is_side_aware_without_moving_existing_fingerprints(tmp_path: Path) -> None:
    src = 'const k = "sk-proj-abcdefghijklmnop1234567890";\n'
    # TS-only, no frontend detected: the file may be server code, so do not claim it ships to visitors.
    ts_only = _ts_run(tmp_path, "src/a.ts", src)
    assert "every visitor" not in ts_only[0].message
    assert "committed" in ts_only[0].message
    # Every profile that fired BEFORE #1082 keeps its message byte-identical. `fingerprint()` hashes
    # `message[:120]`, so rewording it would orphan existing baselines and triage verdicts.
    for features in ({"frontend"}, {"javascript"}, {"express", "javascript", "typescript"}):
        before = _ts_run(tmp_path, "src/a.ts", src, frozenset(features))
        assert before[0].message == _OLD_MESSAGE_OPENAI, features


_OLD_REMEDIATION = (
    "Never place a secret in client code. Proxy the third-party call through "
    "a backend that holds the key server-side (a Supabase Edge Function, a "
    "FastAPI route) and store the value in a secret manager / server env — the "
    "client calls your endpoint, never the third party directly. Rotate the "
    "exposed key immediately. Suppress with `// security: allow-client-side-secret` "
    "only for a confirmed non-secret / fixture value."
)


def test_issue_1082_title_and_remediation_are_side_aware(tmp_path: Path) -> None:
    """#1101 round 1, M1: the TS-only finding said "this may be server code" in its message but kept
    a "client-side JavaScript" title and a "proxy it through a backend" fix, which a backend cannot
    apply. Neither field is fingerprinted, but every pre-#1082 profile still keeps both verbatim."""
    src = 'const k = "sk-proj-abcdefghijklmnop1234567890";\n'
    ts_only = _ts_run(tmp_path, "src/a.ts", src)[0]
    assert "client" not in ts_only.title.lower()
    assert not ts_only.remediation.startswith("Never place a secret in client code")
    assert "environment variable" in ts_only.remediation and "git history" in ts_only.remediation
    assert "Rotate" in ts_only.remediation and "allow-client-side-secret" in ts_only.remediation
    for features in ({"frontend"}, {"javascript"}, {"express", "javascript", "typescript"}):
        before = _ts_run(tmp_path, "src/a.ts", src, frozenset(features))[0]
        assert before.title == ClientSideSecretLiteralGuard.title, features
        assert before.remediation == _OLD_REMEDIATION, features


def test_issue_1082_ts_only_documented_aws_placeholder_is_an_accepted_high(tmp_path: Path) -> None:
    """#1101 round 1, M2, recorded rather than narrowed: the guard has no token-level placeholder
    exclusion, and this suite already pins AWS's documentation key as a positive under `javascript`
    (`test_client_side_secret_literal_fires_aws_and_github`). #1082 extends that to TS-only repos,
    `.d.ts` included. Pinned so the behaviour is a decision, and the pragma is the escape hatch."""
    src = 'declare const EXAMPLE: "AKIAIOSFODNN7EXAMPLE";\n'
    findings = _ts_run(tmp_path / "plain", "src/types.d.ts", src)
    assert [(f.severity, "AWS" in f.message) for f in findings] == [("high", True)]
    assert _ts_run(tmp_path / "pragma", "src/types.d.ts", src + "// security: allow-client-side-secret\n") == []


def test_issue_1082_checklist_applies_when_matches_the_guard(tmp_path: Path) -> None:
    from agentsec.checklist import load_checklist

    item = next(i for i in load_checklist().items if i.id == "6a-no-provider-key-literal-in-client-js")
    for features in ({"frontend"}, {"javascript"}, {"typescript"}, {"python"}, {"go"}):
        guard_applies = ClientSideSecretLiteralGuard().applies(mkprofile(tmp_path, features=features))
        assert bool(set(item.applies_when) & features) is guard_applies, features


def test_issue_1082_real_pipeline_ts_backend_gates_regardless_of_a_stray_js_file(tmp_path: Path) -> None:
    """The #1082 repro through real detect -> select -> run. The incidental `eslint.config.js` used
    to be what switched the guard on; the findings must have the same severity and location with and
    without it. The WORDING still differs, deliberately: the `.js` file adds `javascript`, which keeps
    the pre-#1082 client wording (fingerprint stability), so that dependence is pinned here too."""
    import os

    from agentsec.audit import audit

    def hits(root: Path) -> tuple[dict[str, str], set[bool]]:
        res = audit(root, run_scanners=False, exceptions_path=Path(os.devnull))
        ours = [f for f in res.findings if f.check_id == "client-side-secret-literal"]
        return (
            {f.location.replace("\\", "/"): f.severity for f in ours},
            {"every visitor" in f.message for f in ours},
        )

    results = []
    wordings = []
    for with_js in (False, True):
        root = tmp_path / ("with-js" if with_js else "ts-only")
        (root / "src").mkdir(parents=True)
        (root / "package.json").write_text(
            '{"dependencies": {"express": "4.19.2"}, "devDependencies": {"typescript": "5.4.0"}}\n',
            encoding="utf-8",
        )
        (root / "src" / "server.ts").write_text(
            'const apiKey = "sk-proj-abcdefghijklmnop1234567890";\n'
            'const anth = "sk-ant-api03-abcdefghijklmnop1234567890";\n',
            encoding="utf-8",
        )
        if with_js:
            (root / "eslint.config.js").write_text("export default [];\n", encoding="utf-8")
        found, wording = hits(root)
        results.append(found)
        wordings.append(wording)
    assert results[0] == {"src/server.ts:1:17": "high", "src/server.ts:2:15": "high"}
    assert results[1] == results[0]
    assert wordings == [{False}, {True}]
