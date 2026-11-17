from __future__ import annotations

from agentsec.guards.vite_client_secret import ViteClientSecretGuard
from tests.guards._common import *  # noqa: F401,F403


def test_vite_client_secret_fires_secret_key(tmp_path: Path) -> None:
    (tmp_path / ".env").write_text("VITE_SECRET_KEY=abc\n", encoding="utf-8")
    profile = mkprofile(tmp_path, features={"frontend"})
    findings = ViteClientSecretGuard().run(tmp_path, profile)
    assert len(findings) >= 1
    assert findings[0].rule == "vite-client-secret/vite-prefix-secret"
    assert findings[0].severity == "high"
    assert findings[0].check_id == "vite-client-secret"

def test_vite_client_secret_fires_api_token_in_env_local(tmp_path: Path) -> None:
    (tmp_path / ".env.local").write_text("VITE_API_TOKEN=xyz\n", encoding="utf-8")
    profile = mkprofile(tmp_path, features={"frontend"})
    findings = ViteClientSecretGuard().run(tmp_path, profile)
    assert len(findings) >= 1
    assert findings[0].rule == "vite-client-secret/vite-prefix-secret"

def test_vite_client_secret_fires_private_key_in_env_production(tmp_path: Path) -> None:
    (tmp_path / ".env.production").write_text("VITE_PRIVATE_KEY=rsa\n", encoding="utf-8")
    profile = mkprofile(tmp_path, features={"frontend"})
    findings = ViteClientSecretGuard().run(tmp_path, profile)
    assert len(findings) >= 1
    assert findings[0].rule == "vite-client-secret/vite-prefix-secret"

def test_vite_client_secret_silent_safe_vars(tmp_path: Path) -> None:
    (tmp_path / ".env").write_text(
        "VITE_APP_NAME=MyApp\nVITE_API_URL=https://api.example.com\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"frontend"})
    findings = ViteClientSecretGuard().run(tmp_path, profile)
    assert findings == []

def test_vite_client_secret_silent_supabase_anon_key(tmp_path: Path) -> None:
    # T2a precision: the Supabase ANON_KEY is a public role:anon JWT, designed to ship to the
    # browser (gated by RLS) — not a secret. Was a false positive (matched the KEY pattern).
    (tmp_path / ".env").write_text("VITE_SUPABASE_ANON_KEY=eyJhbGciOi.public.jwt\n", encoding="utf-8")
    assert ViteClientSecretGuard().run(tmp_path, mkprofile(tmp_path, features={"frontend"})) == []

def test_vite_client_secret_still_fires_anon_named_secret(tmp_path: Path) -> None:
    # ...but the exemption is specific to ANON_KEY — a genuinely-secret var that merely contains
    # "anon" (or a real VITE_STRIPE_SECRET_KEY) MUST still fire (no over-exemption).
    (tmp_path / ".env").write_text(
        "VITE_ANONYMIZER_SECRET=shhh\nVITE_STRIPE_SECRET_KEY=sk_live_x\n", encoding="utf-8"
    )
    findings = ViteClientSecretGuard().run(tmp_path, mkprofile(tmp_path, features={"frontend"}))
    assert len(findings) == 2

def test_vite_client_secret_silent_no_vite_prefix(tmp_path: Path) -> None:
    (tmp_path / ".env").write_text("SECRET_KEY=abc\n", encoding="utf-8")
    profile = mkprofile(tmp_path, features={"frontend"})
    findings = ViteClientSecretGuard().run(tmp_path, profile)
    assert findings == []

def test_vite_client_secret_pragma_silences(tmp_path: Path) -> None:
    # The documented form: a `#` comment line in the .env file. A bare `security: allow-…` line
    # (what this test wrote before #424 E2) is not a dotenv comment and no longer counts.
    content = "VITE_SECRET_KEY=abc\n# security: allow-vite-client-secret\n"
    (tmp_path / ".env").write_text(content, encoding="utf-8")
    profile = mkprofile(tmp_path, features={"frontend"})
    findings = ViteClientSecretGuard().run(tmp_path, profile)
    assert findings == []

def test_vite_client_secret_applies_gate(tmp_path: Path) -> None:
    (tmp_path / ".env").write_text("VITE_SECRET_KEY=abc\n", encoding="utf-8")
    profile_no_fe = mkprofile(tmp_path, features={"python", "fastapi"})
    assert not ViteClientSecretGuard().applies(profile_no_fe)
    profile_fe = mkprofile(tmp_path, features={"frontend"})
    assert ViteClientSecretGuard().applies(profile_fe)

def test_vite_client_secret_multiple_findings(tmp_path: Path) -> None:
    content = "VITE_SECRET_KEY=abc\nVITE_API_TOKEN=xyz\nVITE_PRIVATE_KEY=rsa\n"
    (tmp_path / ".env").write_text(content, encoding="utf-8")
    profile = mkprofile(tmp_path, features={"frontend"})
    findings = ViteClientSecretGuard().run(tmp_path, profile)
    assert len(findings) == 3
    assert all(f.rule == "vite-client-secret/vite-prefix-secret" for f in findings)



def test_vite_client_secret_pragma_outside_a_comment_does_not_suppress(tmp_path: Path) -> None:
    # #424 E2: a quoted value that merely QUOTES the opt-out (help text) and a bare non-comment
    # line are dotenv content, not comments — under the raw-text match either one blinded the file.
    content = (
        "VITE_SECRET_KEY=abc\n"
        'VITE_HELP="opt out with # security: allow-vite-client-secret"\n'
        "security: allow-vite-client-secret\n"
    )
    (tmp_path / ".env").write_text(content, encoding="utf-8")
    profile = mkprofile(tmp_path, features={"frontend"})
    findings = ViteClientSecretGuard().run(tmp_path, profile)
    assert [f.rule for f in findings] == ["vite-client-secret/vite-prefix-secret"]
