from __future__ import annotations

from agentsec.guards.next_public_client_secret import NextPublicClientSecretGuard
from tests.guards._common import *  # noqa: F401,F403


def test_next_public_client_secret_fires_secret_key(tmp_path: Path) -> None:
    (tmp_path / ".env").write_text("NEXT_PUBLIC_SECRET_KEY=abc\n", encoding="utf-8")
    profile = mkprofile(tmp_path, features={"nextjs"})
    findings = NextPublicClientSecretGuard().run(tmp_path, profile)
    assert len(findings) >= 1
    assert findings[0].rule == "next-public-client-secret/next-public-prefix-secret"
    assert findings[0].severity == "high"
    assert findings[0].check_id == "next-public-client-secret"


def test_next_public_client_secret_fires_api_token_in_env_local(tmp_path: Path) -> None:
    (tmp_path / ".env.local").write_text("NEXT_PUBLIC_API_TOKEN=xyz\n", encoding="utf-8")
    profile = mkprofile(tmp_path, features={"nextjs"})
    findings = NextPublicClientSecretGuard().run(tmp_path, profile)
    assert len(findings) >= 1


def test_next_public_client_secret_fires_stripe_secret_key(tmp_path: Path) -> None:
    (tmp_path / ".env.production").write_text(
        "NEXT_PUBLIC_STRIPE_SECRET_KEY=sk_live_abc123\n", encoding="utf-8"
    )
    profile = mkprofile(tmp_path, features={"nextjs"})
    findings = NextPublicClientSecretGuard().run(tmp_path, profile)
    assert len(findings) >= 1


def test_next_public_client_secret_silent_safe_vars(tmp_path: Path) -> None:
    (tmp_path / ".env").write_text(
        "NEXT_PUBLIC_APP_NAME=MyApp\nNEXT_PUBLIC_API_URL=https://api.example.com\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"nextjs"})
    assert NextPublicClientSecretGuard().run(tmp_path, profile) == []


def test_next_public_client_secret_silent_stripe_publishable_key(tmp_path: Path) -> None:
    (tmp_path / ".env").write_text(
        "NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY=pk_live_abc123\n", encoding="utf-8"
    )
    profile = mkprofile(tmp_path, features={"nextjs"})
    assert NextPublicClientSecretGuard().run(tmp_path, profile) == []


def test_next_public_client_secret_silent_supabase_anon_key(tmp_path: Path) -> None:
    (tmp_path / ".env").write_text(
        "NEXT_PUBLIC_SUPABASE_ANON_KEY=eyJhbGciOi.public.jwt\n", encoding="utf-8"
    )
    profile = mkprofile(tmp_path, features={"nextjs"})
    assert NextPublicClientSecretGuard().run(tmp_path, profile) == []


def test_next_public_client_secret_still_fires_anon_named_secret(tmp_path: Path) -> None:
    # The ANON_KEY exemption is specific — a genuinely-secret var that merely contains
    # "anon" must still fire (no over-exemption).
    (tmp_path / ".env").write_text(
        "NEXT_PUBLIC_ANONYMIZER_SECRET=shhh\n", encoding="utf-8"
    )
    profile = mkprofile(tmp_path, features={"nextjs"})
    findings = NextPublicClientSecretGuard().run(tmp_path, profile)
    assert len(findings) == 1


def test_next_public_client_secret_silent_no_next_public_prefix(tmp_path: Path) -> None:
    (tmp_path / ".env").write_text("SECRET_KEY=abc\n", encoding="utf-8")
    profile = mkprofile(tmp_path, features={"nextjs"})
    assert NextPublicClientSecretGuard().run(tmp_path, profile) == []


def test_next_public_client_secret_pragma_silences(tmp_path: Path) -> None:
    (tmp_path / ".env").write_text(
        "# security: allow-next-public-client-secret\nNEXT_PUBLIC_SECRET_KEY=abc\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"nextjs"})
    assert NextPublicClientSecretGuard().run(tmp_path, profile) == []


def test_next_public_client_secret_not_applicable_without_frontend_or_nextjs() -> None:
    prof = mkprofile(Path("/tmp"), features={"python"})
    assert not NextPublicClientSecretGuard().applies(prof)


def test_next_public_client_secret_applies_via_frontend_feature(tmp_path: Path) -> None:
    # A generic "frontend" detection (not the nextjs-specific one) still gates this guard on —
    # the NEXT_PUBLIC_ prefix itself is unambiguous, so no false positives from the broader gate.
    (tmp_path / ".env").write_text("NEXT_PUBLIC_SECRET_KEY=abc\n", encoding="utf-8")
    profile = mkprofile(tmp_path, features={"frontend"})
    assert len(NextPublicClientSecretGuard().run(tmp_path, profile)) == 1
