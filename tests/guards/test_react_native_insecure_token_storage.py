from __future__ import annotations

from agentsec.guards.react_native_insecure_token_storage import ReactNativeInsecureTokenStorageGuard
from tests.guards._common import *  # noqa: F401,F403


def _rn_prof(root: Path) -> StackProfile:
    return mkprofile(root, features={"react-native"})


def test_fires_on_async_storage_set_item_token(tmp_path: Path) -> None:
    (tmp_path / "auth.js").write_text(
        'AsyncStorage.setItem("token", jwt);', encoding="utf-8"
    )
    findings = ReactNativeInsecureTokenStorageGuard().run(tmp_path, _rn_prof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "react-native-insecure-token-storage/async-storage-setitem"
    assert findings[0].severity == "high"


def test_silent_on_multi_set_disclosed_scope_limit(tmp_path: Path) -> None:
    # Disclosed, not fixed: multiSet's nested-array key names are a different shape than
    # setItem's simple two-argument call this guard's regex targets.
    (tmp_path / "auth.ts").write_text(
        "AsyncStorage.multiSet([['auth_token', token], ['user_id', id]]);", encoding="utf-8"
    )
    assert ReactNativeInsecureTokenStorageGuard().run(tmp_path, _rn_prof(tmp_path)) == []


def test_fires_on_refresh_token(tmp_path: Path) -> None:
    (tmp_path / "session.jsx").write_text(
        "await AsyncStorage.setItem('refresh_token', resp.refreshToken);", encoding="utf-8"
    )
    findings = ReactNativeInsecureTokenStorageGuard().run(tmp_path, _rn_prof(tmp_path))
    assert len(findings) == 1


def test_silent_on_theme_preference(tmp_path: Path) -> None:
    (tmp_path / "prefs.js").write_text(
        'AsyncStorage.setItem("theme", "dark");', encoding="utf-8"
    )
    assert ReactNativeInsecureTokenStorageGuard().run(tmp_path, _rn_prof(tmp_path)) == []


def test_silent_on_onboarding_flag(tmp_path: Path) -> None:
    (tmp_path / "onboarding.tsx").write_text(
        'AsyncStorage.setItem("hasSeenOnboarding", "true");', encoding="utf-8"
    )
    assert ReactNativeInsecureTokenStorageGuard().run(tmp_path, _rn_prof(tmp_path)) == []


def test_silent_on_bare_auth_substring(tmp_path: Path) -> None:
    # FP-bait: "authorFlag" contains "author" not a word-boundaried "auth" — mirrors
    # token-in-localstorage's own reauth/authorFlag exclusion exactly.
    (tmp_path / "flags.js").write_text(
        'AsyncStorage.setItem("authorFlag", "true");', encoding="utf-8"
    )
    assert ReactNativeInsecureTokenStorageGuard().run(tmp_path, _rn_prof(tmp_path)) == []


def test_fires_on_auth_branch_only_keys(tmp_path: Path) -> None:
    # DISCRIMINATING test for the `auth`/`authorization` branch (#904 M1): none of these keys
    # contains another credential stem, so they can only fire via the auth branch. `authKey`/
    # `authData` were silently dropped by the old `(?![a-z])` boundary under IGNORECASE; the
    # scoped case-sensitive boundary restores them. Kept in sync with token-in-localstorage.
    keys = ("auth", "authKey", "authData", "authState", "authorization")
    (tmp_path / "auth.js").write_text(
        "\n".join(f'AsyncStorage.setItem("{k}", v);' for k in keys), encoding="utf-8"
    )
    findings = ReactNativeInsecureTokenStorageGuard().run(tmp_path, _rn_prof(tmp_path))
    assert len(findings) == len(keys)


def test_silent_on_author_family(tmp_path: Path) -> None:
    # Widening direction (rule 1): the auth branch now catches camelCase humps and the
    # explicit `authorization` — assert the `author…`/`reauth` family it must NOT catch
    # stays silent (authorId/authorName are common non-credential fields).
    keys = ("authorId", "authorName", "authored", "reauth")
    (tmp_path / "blog.js").write_text(
        "\n".join(f'AsyncStorage.setItem("{k}", v);' for k in keys), encoding="utf-8"
    )
    assert ReactNativeInsecureTokenStorageGuard().run(tmp_path, _rn_prof(tmp_path)) == []


def test_silent_on_nonproduct_path(tmp_path: Path) -> None:
    d = tmp_path / "examples"
    d.mkdir()
    (d / "demo.js").write_text('AsyncStorage.setItem("token", "demo");', encoding="utf-8")
    assert ReactNativeInsecureTokenStorageGuard().run(tmp_path, _rn_prof(tmp_path)) == []


def test_pragma_silences(tmp_path: Path) -> None:
    (tmp_path / "legacy.js").write_text(
        "// security: allow-async-storage-token\n"
        'AsyncStorage.setItem("auth_token", t);\n',
        encoding="utf-8",
    )
    assert ReactNativeInsecureTokenStorageGuard().run(tmp_path, _rn_prof(tmp_path)) == []


def test_not_applicable_without_react_native() -> None:
    prof = mkprofile(Path("/tmp"), features={"javascript", "frontend"})
    assert not ReactNativeInsecureTokenStorageGuard().applies(prof)


def test_multiple_findings_one_per_line(tmp_path: Path) -> None:
    content = (
        'AsyncStorage.setItem("token", a);\n'
        'AsyncStorage.setItem("theme", "dark");\n'
        'AsyncStorage.setItem("refresh_token", b);\n'
    )
    (tmp_path / "multi.tsx").write_text(content, encoding="utf-8")
    findings = ReactNativeInsecureTokenStorageGuard().run(tmp_path, _rn_prof(tmp_path))
    assert len(findings) == 2
