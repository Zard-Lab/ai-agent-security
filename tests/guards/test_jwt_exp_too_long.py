from __future__ import annotations

from agentsec.guards.jwt_exp_too_long import JwtExpTooLongGuard
from tests.guards._common import *  # noqa: F401,F403


def test_jwt_exp_too_long_fires(tmp_path: Path) -> None:
    (tmp_path / "auth.py").write_text(
        "ACCESS_TOKEN_EXPIRE_MINUTES = 10080\n", encoding="utf-8"
    )
    p = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    f = JwtExpTooLongGuard().run(tmp_path, p)
    assert any("jwt-exp-too-long" in x.check_id for x in f)
    assert f[0].rule == "jwt-exp-too-long/access-token-lifetime-too-long"
    assert f[0].severity == "high"

def test_jwt_exp_too_long_non_token_file_silent(tmp_path: Path) -> None:
    # T3 precision: an `expiry` timedelta in a file with NO JWT/token context is some other TTL
    # (a memory record, a cache entry) — not a token lifetime. Must be silent (was a FP).
    (tmp_path / "memory_expiration.py").write_text(
        "from datetime import datetime, timedelta\n"
        "def record_expiry(weeks):\n"
        "    expiry = datetime.now() + timedelta(weeks=weeks, days=3)\n"
        "    return expiry\n",
        encoding="utf-8",
    )
    p = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    assert JwtExpTooLongGuard().run(tmp_path, p) == []

def test_jwt_exp_too_long_token_file_expires_delta_fires(tmp_path: Path) -> None:
    # ...but a long `expires_delta` in a real token file (no "token" in the var name) MUST fire (no FN).
    (tmp_path / "auth.py").write_text(
        "import jwt\nfrom datetime import timedelta\n"
        "def create_access_token(data):\n"
        "    expires_delta = timedelta(days=30)\n"
        "    return jwt.encode(data, 'k')\n",
        encoding="utf-8",
    )
    p = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    rules = [x.rule for x in JwtExpTooLongGuard().run(tmp_path, p)]
    assert "jwt-exp-too-long/access-token-lifetime-too-long" in rules

def test_jwt_exp_too_long_silent_short(tmp_path: Path) -> None:
    (tmp_path / "auth.py").write_text(
        "ACCESS_TOKEN_EXPIRE_MINUTES = 30\n", encoding="utf-8"
    )
    p = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    assert JwtExpTooLongGuard().run(tmp_path, p) == []

def test_jwt_exp_too_long_silent_refresh(tmp_path: Path) -> None:
    (tmp_path / "auth.py").write_text(
        "REFRESH_TOKEN_EXPIRE_DAYS = 30\n", encoding="utf-8"
    )
    p = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    assert JwtExpTooLongGuard().run(tmp_path, p) == []

def test_jwt_exp_too_long_pragma(tmp_path: Path) -> None:
    (tmp_path / "auth.py").write_text(
        "ACCESS_TOKEN_EXPIRE_MINUTES = 10080  # security: allow-long-lived-token\n",
        encoding="utf-8",
    )
    p = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    assert JwtExpTooLongGuard().run(tmp_path, p) == []

def test_jwt_exp_too_long_refresh_const_not_flagged(tmp_path: Path) -> None:
    # #423 FP-bait: REFRESH_TOKEN_EXPIRE_MINUTES is a refresh-token lifetime (allowed long) —
    # the const arm must not read TOKEN_EXPIRE_MINUTES inside it as an access-token setting.
    (tmp_path / "auth.py").write_text(
        "REFRESH_TOKEN_EXPIRE_MINUTES = 43200\n", encoding="utf-8"
    )
    p = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    assert JwtExpTooLongGuard().run(tmp_path, p) == []

def test_jwt_exp_too_long_prefixed_access_const_still_fires(tmp_path: Path) -> None:
    # PR #447 review: a legitimately-prefixed SETTINGS_ACCESS_TOKEN_EXPIRE_MINUTES must still
    # fire — the left-boundary must scope to the bare TOKEN arm only, not the ACCESS arm.
    (tmp_path / "auth.py").write_text(
        "SETTINGS_ACCESS_TOKEN_EXPIRE_MINUTES = 10080\n", encoding="utf-8"
    )
    p = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    f = JwtExpTooLongGuard().run(tmp_path, p)
    assert any(x.rule == "jwt-exp-too-long/access-token-lifetime-too-long" for x in f)

def test_jwt_exp_too_long_one_day_at_limit_not_flagged(tmp_path: Path) -> None:
    # #423 FP-bait: timedelta(days=1) is exactly 24h — at the limit, not over it. Consistent
    # with hours=24 / minutes=1440 not firing.
    (tmp_path / "auth.py").write_text(
        "import jwt\n"
        "from datetime import timedelta\n"
        "access_token_expires = timedelta(days=1)\n",
        encoding="utf-8",
    )
    p = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    assert JwtExpTooLongGuard().run(tmp_path, p) == []

def test_jwt_exp_too_long_applies_gate() -> None:
    p = mkprofile(Path("."), features=set())
    assert not JwtExpTooLongGuard().applies(p)



def test_jwt_exp_trailing_comment_does_not_silence_a_real_finding(tmp_path: Path) -> None:
    # Regression (#447 review): `_REFRESH_KEYWORD` was searched against the whole raw line, so a
    # trailing comment silenced a genuine over-long ACCESS token. This is a 30-day access token.
    (tmp_path / "cfg.py").write_text(
        "ACCESS_TOKEN_EXPIRE_MINUTES = 43200  # TODO: move to a refresh-token flow\n",
        encoding="utf-8",
    )
    p = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    assert len(JwtExpTooLongGuard().run(tmp_path, p)) == 1


def test_jwt_exp_timedelta_components_are_summed(tmp_path: Path) -> None:
    # Regression (#447 review): days/hours/minutes were mutually exclusive arms, each ending in a
    # `continue`, so `timedelta(days=1, hours=12)` matched the days arm, failed its `days > 1`
    # test and skipped the rest — 36 hours missed, while the identical `timedelta(hours=36)` fired.
    (tmp_path / "a.py").write_text(
        "from datetime import timedelta\nACCESS_TOKEN_EXPIRE = timedelta(days=1, hours=12)\n",
        encoding="utf-8",
    )
    p = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    assert len(JwtExpTooLongGuard().run(tmp_path, p)) == 1


def test_jwt_exp_exactly_one_day_is_at_the_limit(tmp_path: Path) -> None:
    # FP-bait: `timedelta(days=1)` is exactly 24h — at the limit, not over it. The summing must
    # keep that threshold, and a refresh token stays exempt at any duration.
    (tmp_path / "a.py").write_text(
        "from datetime import timedelta\nACCESS_TOKEN_EXPIRE = timedelta(days=1)\n", encoding="utf-8"
    )
    (tmp_path / "b.py").write_text(
        "from datetime import timedelta\nREFRESH_TOKEN_EXPIRE = timedelta(days=30)\n", encoding="utf-8"
    )
    p = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    assert JwtExpTooLongGuard().run(tmp_path, p) == []


def test_jwt_exp_too_long_pragma_quoted_in_a_string_on_the_line_still_fires(tmp_path: Path) -> None:
    # The pragma phrase in a string on the flagged line is not a comment, so it must not suppress (#1040).
    p = mkprofile(tmp_path, features={"python"}, python_dirs=["."])

    def run(note: str) -> list:
        (tmp_path / "auth.py").write_text(
            f'ACCESS_TOKEN_EXPIRE_MINUTES = 10080; _note = "{note}"\n', encoding="utf-8"
        )
        return JwtExpTooLongGuard().run(tmp_path, p)

    assert len(run("neutral")) == 1
    findings = run("# security: allow-long-lived-token")
    assert len(findings) == 1
    assert findings[0].location.endswith("auth.py:1")
