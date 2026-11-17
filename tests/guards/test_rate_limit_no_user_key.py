from __future__ import annotations

from agentsec.guards.rate_limit_no_user_key import RateLimitNoUserKeyGuard
from tests.guards._common import *  # noqa: F401,F403


def test_rate_limit_no_user_key_fires(tmp_path: Path) -> None:
    (tmp_path / "limiter.py").write_text(
        "from slowapi import Limiter\nfrom slowapi.util import get_remote_address\n"
        "limiter = Limiter(key_func=get_remote_address)\n",
        encoding="utf-8",
    )
    findings = RateLimitNoUserKeyGuard().run(tmp_path, _python_nodirs_prof(tmp_path))
    assert any(f.rule == "rate-limit-no-user-key/ip-only-key-func" for f in findings)

def test_rate_limit_no_user_key_user_key_silences(tmp_path: Path) -> None:
    (tmp_path / "limiter.py").write_text(
        "from slowapi import Limiter\nfrom slowapi.util import get_remote_address\n"
        "def get_user_id(request): return request.state.user_id\n"
        "limiter = Limiter(key_func=get_user_id)\n",
        encoding="utf-8",
    )
    assert RateLimitNoUserKeyGuard().run(tmp_path, _python_nodirs_prof(tmp_path)) == []

def test_rate_limit_no_user_key_no_slowapi_silent(tmp_path: Path) -> None:
    (tmp_path / "main.py").write_text("from fastapi import FastAPI\napp = FastAPI()\n", encoding="utf-8")
    assert RateLimitNoUserKeyGuard().run(tmp_path, _python_nodirs_prof(tmp_path)) == []

def test_rate_limit_no_user_key_multiline_limiter_fires(tmp_path: Path) -> None:
    # Regression (issue #422 S4): key_func= on a continuation line of a black-wrapped
    # Limiter( call was treated as "no key_func found" and the guard stayed silent.
    (tmp_path / "limiter.py").write_text(
        "from slowapi import Limiter\n"
        "from slowapi.util import get_remote_address\n"
        "limiter = Limiter(\n"
        "    key_func=get_remote_address,\n"
        ")\n",
        encoding="utf-8",
    )
    findings = RateLimitNoUserKeyGuard().run(tmp_path, _python_nodirs_prof(tmp_path))
    assert any(f.rule == "rate-limit-no-user-key/ip-only-key-func" for f in findings)
    assert findings[0].location.endswith("limiter.py:3")

def test_rate_limit_no_user_key_multiline_user_key_silent(tmp_path: Path) -> None:
    # FP-bait: a multi-line Limiter( with a user-scoped key func must not fire.
    (tmp_path / "limiter.py").write_text(
        "from slowapi import Limiter\n"
        "def get_user_id(request): return request.state.user_id\n"
        "limiter = Limiter(\n"
        "    key_func=get_user_id,\n"
        ")\n",
        encoding="utf-8",
    )
    assert RateLimitNoUserKeyGuard().run(tmp_path, _python_nodirs_prof(tmp_path)) == []


def test_rate_limit_no_user_key_comment_paren_in_limiter_fires(tmp_path: Path) -> None:
    # Regression (#437 review High-2): a stray `)` inside a `#` comment within the wrapped
    # Limiter( call ended the join before key_func=, leaving key_funcs empty so the guard
    # bailed out for the whole file.
    (tmp_path / "limiter.py").write_text(
        "from slowapi import Limiter\n"
        "from slowapi.util import get_remote_address\n"
        "limiter = Limiter(\n"
        "    # migrated from old setup)\n"
        "    key_func=get_remote_address,\n"
        ")\n",
        encoding="utf-8",
    )
    findings = RateLimitNoUserKeyGuard().run(tmp_path, _python_nodirs_prof(tmp_path))
    assert any(f.rule == "rate-limit-no-user-key/ip-only-key-func" for f in findings)

def test_rate_limit_no_user_key_commented_key_func_not_counted(tmp_path: Path) -> None:
    # A key_func= that exists ONLY in a comment must not count as configured: the joined
    # call text is comment-stripped, so this Limiter has no key_func at all.
    (tmp_path / "limiter.py").write_text(
        "from slowapi import Limiter\n"
        "limiter = Limiter(\n"
        "    # key_func=get_user_id,\n"
        ")\n",
        encoding="utf-8",
    )
    findings = RateLimitNoUserKeyGuard().run(tmp_path, _python_nodirs_prof(tmp_path))
    assert not any(f.rule == "rate-limit-no-user-key/ip-only-key-func" for f in findings)
