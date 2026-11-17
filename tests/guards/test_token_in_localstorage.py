from __future__ import annotations

from agentsec.guards.token_in_localstorage import TokenInLocalstorageGuard
from tests.guards._common import *  # noqa: F401,F403


def test_token_in_localstorage_fires_localstorage(tmp_path: Path) -> None:
    (tmp_path / "auth.js").write_text('localStorage.setItem("token", jwt)', encoding="utf-8")
    profile = mkprofile(tmp_path, features={"frontend"})
    findings = TokenInLocalstorageGuard().run(tmp_path, profile)
    assert len(findings) >= 1
    assert findings[0].rule == "token-in-localstorage/localstorage-setitem"
    assert findings[0].severity == "high"

def test_token_in_localstorage_fires_sessionstorage(tmp_path: Path) -> None:
    (tmp_path / "session.ts").write_text("sessionStorage.setItem('jwt', accessToken)", encoding="utf-8")
    profile = mkprofile(tmp_path, features={"frontend"})
    findings = TokenInLocalstorageGuard().run(tmp_path, profile)
    assert len(findings) >= 1
    assert findings[0].rule == "token-in-localstorage/localstorage-setitem"

def test_token_in_localstorage_fires_auth_token(tmp_path: Path) -> None:
    (tmp_path / "api.jsx").write_text("localStorage.setItem('auth_token', resp.token)", encoding="utf-8")
    profile = mkprofile(tmp_path, features={"javascript"})
    findings = TokenInLocalstorageGuard().run(tmp_path, profile)
    assert len(findings) >= 1

def test_token_in_localstorage_silent_theme(tmp_path: Path) -> None:
    (tmp_path / "prefs.js").write_text('localStorage.setItem("theme", "dark")', encoding="utf-8")
    profile = mkprofile(tmp_path, features={"frontend"})
    findings = TokenInLocalstorageGuard().run(tmp_path, profile)
    assert findings == []

def test_token_in_localstorage_silent_lang(tmp_path: Path) -> None:
    (tmp_path / "i18n.ts").write_text('sessionStorage.setItem("cart", JSON.stringify(cart))', encoding="utf-8")
    profile = mkprofile(tmp_path, features={"frontend"})
    findings = TokenInLocalstorageGuard().run(tmp_path, profile)
    assert findings == []

def test_token_in_localstorage_pragma_silences(tmp_path: Path) -> None:
    content = 'localStorage.setItem("auth_token", t)\n// security: allow-token-in-localstorage\n'
    (tmp_path / "legacy.jsx").write_text(content, encoding="utf-8")
    profile = mkprofile(tmp_path, features={"frontend"})
    findings = TokenInLocalstorageGuard().run(tmp_path, profile)
    assert findings == []

def test_token_in_localstorage_applies_gate(tmp_path: Path) -> None:
    guard = TokenInLocalstorageGuard()
    assert guard.applies(mkprofile(tmp_path, features={"frontend"})) is True
    assert guard.applies(mkprofile(tmp_path, features={"javascript"})) is True
    assert guard.applies(mkprofile(tmp_path, features={"python", "fastapi"})) is False

def test_token_in_localstorage_multiple_lines(tmp_path: Path) -> None:
    content = (
        'localStorage.setItem("token", a)\n'
        'localStorage.setItem("theme", "dark")\n'
        'sessionStorage.setItem("refresh_token", b)\n'
    )
    (tmp_path / "multi.tsx").write_text(content, encoding="utf-8")
    profile = mkprofile(tmp_path, features={"frontend"})
    findings = TokenInLocalstorageGuard().run(tmp_path, profile)
    assert len(findings) == 2

def test_token_in_localstorage_ignores_noncredential_substrings(tmp_path: Path) -> None:
    # tightened keywords: `reauth` (admin_reauth_ts) and `session-id` are not credentials.
    (tmp_path / "s.tsx").write_text(
        'localStorage.setItem("admin_reauth_ts_v1", t)\n'
        'localStorage.setItem("hwh-widget-session-id", id)\n',
        encoding="utf-8",
    )
    assert TokenInLocalstorageGuard().run(tmp_path, mkprofile(tmp_path, features={"frontend"})) == []


def test_token_in_localstorage_silent_on_commented_example(tmp_path: Path) -> None:
    # FP-bait (#424): a commented-out setItem of a token must not fire.
    (tmp_path / "auth.js").write_text(
        '// localStorage.setItem("token", jwt)\n'
        "const x = 1;\n",
        encoding="utf-8",
    )
    assert TokenInLocalstorageGuard().run(tmp_path, mkprofile(tmp_path, features={"frontend"})) == []


def test_token_in_localstorage_silent_on_author_flag(tmp_path: Path) -> None:
    # FP-bait: "authorFlag" contains "auth" as a substring but continues into a real word
    # ("author"), not a credential-shaped key. The left-only word-boundary this guard used
    # to have still matched it (nothing precedes "auth" in "authorFlag" either) — found
    # while building the React Native sibling guard's mirrored regex.
    (tmp_path / "flags.js").write_text(
        'localStorage.setItem("authorFlag", "true")\n', encoding="utf-8"
    )
    assert TokenInLocalstorageGuard().run(tmp_path, mkprofile(tmp_path, features={"frontend"})) == []


def test_token_in_localstorage_fires_auth_branch_only_keys(tmp_path: Path) -> None:
    # DISCRIMINATING test for the `auth`/`authorization` branch (CLAUDE.md rule 1, #904 M1):
    # none of these keys contains any other credential stem (`token`/`jwt`/`secret`/`api_key`
    # …), so they can only fire via the auth branch this boundary governs. The prior "still
    # fires" test used `auth_token`/`authToken`, which fire via `token` regardless — it never
    # exercised this branch, and passed even with the whole `auth` alternative deleted.
    # `authKey`/`authData` were being *silently dropped* by the old `(?![a-z])` right boundary
    # under IGNORECASE; the scoped case-sensitive boundary restores them.
    keys = ("auth", "authKey", "authData", "authState", "authorization")
    (tmp_path / "auth.js").write_text(
        "\n".join(f'localStorage.setItem("{k}", v)' for k in keys), encoding="utf-8"
    )
    findings = TokenInLocalstorageGuard().run(tmp_path, mkprofile(tmp_path, features={"frontend"}))
    assert len(findings) == len(keys)


def test_token_in_localstorage_silent_on_author_family(tmp_path: Path) -> None:
    # Widening direction (rule 1): the auth branch now also catches camelCase humps
    # (`authKey`) and the explicit word `authorization`. Assert the `author…`/`reauth` family
    # it must NOT catch stays silent — `authorId`/`authorName` are extremely common
    # non-credential fields, and re-firing on them is exactly the FP the boundary exists to kill.
    keys = ("authorId", "authorName", "authored", "authoring", "reauth")
    (tmp_path / "blog.js").write_text(
        "\n".join(f'localStorage.setItem("{k}", v)' for k in keys), encoding="utf-8"
    )
    assert TokenInLocalstorageGuard().run(tmp_path, mkprofile(tmp_path, features={"frontend"})) == []
