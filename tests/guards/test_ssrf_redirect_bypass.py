"""Tests for SsrfRedirectBypassGuard — planted-violation + FP-bait."""
from __future__ import annotations

import pytest

from agentsec.guards.ssrf_redirect_bypass import SsrfRedirectBypassGuard
from tests.guards._common import *  # noqa: F401,F403


def _prof(root: Path) -> StackProfile:
    return mkprofile(root, features={"python"}, python_dirs=["."])


def test_validate_then_fetch_no_redirect_control_fires(tmp_path: Path) -> None:
    (tmp_path / "fetcher.py").write_text(
        "import requests\n\n"
        "def fetch_document(url):\n"
        "    if not validate_safe_url(url):\n"
        "        raise ValueError('unsafe url')\n"
        "    response = requests.get(url)\n"
        "    return response.text\n",
        encoding="utf-8",
    )
    findings = SsrfRedirectBypassGuard().run(tmp_path, _prof(tmp_path))
    hit = next(f for f in findings if f.rule == "ssrf-redirect-bypass/redirect-not-disabled")
    assert hit.severity == "high"


def test_allow_redirects_false_is_safe(tmp_path: Path) -> None:
    """FP-bait: the caller explicitly disables redirects -- safe."""
    (tmp_path / "fetcher.py").write_text(
        "import requests\n\n"
        "def fetch_document(url):\n"
        "    if not validate_safe_url(url):\n"
        "        raise ValueError('unsafe url')\n"
        "    response = requests.get(url, allow_redirects=False)\n"
        "    return response.text\n",
        encoding="utf-8",
    )
    findings = SsrfRedirectBypassGuard().run(tmp_path, _prof(tmp_path))
    assert findings == []


def test_max_redirects_zero_is_safe(tmp_path: Path) -> None:
    (tmp_path / "fetcher.py").write_text(
        "def fetch_document(url, session):\n"
        "    if not validate_safe_url(url):\n"
        "        raise ValueError('unsafe url')\n"
        "    response = session.get(url, max_redirects=0)\n"
        "    return response.text\n",
        encoding="utf-8",
    )
    findings = SsrfRedirectBypassGuard().run(tmp_path, _prof(tmp_path))
    assert findings == []


def test_no_validator_call_is_safe(tmp_path: Path) -> None:
    """FP-bait: a plain fetch with no preceding SSRF-guard call is out of this guard's
    scope entirely (that's ssrf-general's job)."""
    (tmp_path / "fetcher.py").write_text(
        "import requests\n\n"
        "def fetch_document(url):\n"
        "    response = requests.get(url)\n"
        "    return response.text\n",
        encoding="utf-8",
    )
    findings = SsrfRedirectBypassGuard().run(tmp_path, _prof(tmp_path))
    assert findings == []


def test_fetch_before_validator_in_different_function_is_safe(tmp_path: Path) -> None:
    """FP-bait: the validator and fetch are in different, unrelated functions -- not the
    same-function validate-then-fetch shape."""
    (tmp_path / "fetcher.py").write_text(
        "import requests\n\n"
        "def check(url):\n"
        "    return validate_safe_url(url)\n\n"
        "def fetch_document(url):\n"
        "    response = requests.get(url)\n"
        "    return response.text\n",
        encoding="utf-8",
    )
    findings = SsrfRedirectBypassGuard().run(tmp_path, _prof(tmp_path))
    assert findings == []


def test_ts_validate_then_fetch_fires(tmp_path: Path) -> None:
    (tmp_path / "fetcher.ts").write_text(
        "if (validateSafeUrl(url)) {\n"
        "  const res = await fetch(url);\n"
        "}\n",
        encoding="utf-8",
    )
    prof = mkprofile(tmp_path, features={"typescript"}, python_dirs=["."])
    findings = SsrfRedirectBypassGuard().run(tmp_path, prof)
    assert any(f.rule == "ssrf-redirect-bypass/redirect-not-disabled" for f in findings)


def test_ts_redirect_manual_is_safe(tmp_path: Path) -> None:
    (tmp_path / "fetcher.ts").write_text(
        "if (validateSafeUrl(url)) {\n"
        "  const res = await fetch(url, { redirect: 'manual' });\n"
        "}\n",
        encoding="utf-8",
    )
    prof = mkprofile(tmp_path, features={"typescript"}, python_dirs=["."])
    findings = SsrfRedirectBypassGuard().run(tmp_path, prof)
    assert findings == []


def test_pragma_suppresses_finding(tmp_path: Path) -> None:
    (tmp_path / "fetcher.py").write_text(
        "# security: allow-ssrf-redirect-bypass\n"
        "import requests\n\n"
        "def fetch_document(url):\n"
        "    if not validate_safe_url(url):\n"
        "        raise ValueError('unsafe url')\n"
        "    response = requests.get(url)\n"
        "    return response.text\n",
        encoding="utf-8",
    )
    findings = SsrfRedirectBypassGuard().run(tmp_path, _prof(tmp_path))
    assert findings == []


# --------------------------------------------------------------------------- PR #963 review round
def _run(tmp_path: Path, body: str) -> list[str]:
    (tmp_path / "app.py").write_text(body, encoding="utf-8")
    return [f.rule for f in SsrfRedirectBypassGuard().run(tmp_path, _prof(tmp_path))]


_FIRES = ["ssrf-redirect-bypass/redirect-not-disabled"]


def test_dict_get_after_validator_is_not_a_fetch(tmp_path: Path) -> None:
    """The review's repro: `config.get("key")` after a validator call is a dict read, not a fetch."""
    assert _run(
        tmp_path,
        "import requests\n\n"
        "def fetch(url, config):\n"
        "    validate_safe_url(url)\n"
        "    timeout = config.get(\"key\")\n"
        "    return timeout\n",
    ) == []


def test_response_header_get_after_validator_is_not_a_fetch(tmp_path: Path) -> None:
    """fastmcp's own SSRF-safe fetcher reads `response.headers.get(...)` after validating."""
    assert _run(
        tmp_path,
        "def read(url, response):\n"
        "    validate_safe_url(url)\n"
        "    return response.headers.get(name_of_header)\n",
    ) == []


def test_metadata_get_with_literal_key_is_not_a_fetch(tmp_path: Path) -> None:
    assert _run(
        tmp_path,
        "def title(url, result):\n"
        "    validate_safe_url(url)\n"
        "    return result.metadata.get('title', url)\n",
    ) == []


def test_requests_get_variable_still_fires(tmp_path: Path) -> None:
    assert _run(
        tmp_path,
        "import requests\n\ndef f(url):\n    validate_safe_url(url)\n    return requests.get(url)\n",
    ) == _FIRES


def test_session_and_client_receivers_still_fire(tmp_path: Path) -> None:
    assert _run(
        tmp_path,
        "def f(self, url):\n    validate_safe_url(url)\n    return self.session.post(url, json={})\n",
    ) == _FIRES
    assert _run(
        tmp_path,
        "def f(self, url):\n    validate_safe_url(url)\n    return self._client.get(url)\n",
    ) == _FIRES


def test_receiver_bound_to_a_client_constructor_still_fires(tmp_path: Path) -> None:
    """`c` carries no client-shaped name, but it is bound to a requests Session."""
    assert _run(
        tmp_path,
        "import requests\n\ndef f(url):\n    validate_safe_url(url)\n"
        "    with requests.Session() as c:\n        return c.get(url)\n",
    ) == _FIRES


def test_request_with_method_literal_uses_the_url_argument(tmp_path: Path) -> None:
    assert _run(
        tmp_path,
        "import requests\n\ndef f(url):\n    validate_safe_url(url)\n"
        "    return requests.request('GET', url)\n",
    ) == _FIRES


def test_urlopen_bare_still_fires(tmp_path: Path) -> None:
    assert _run(
        tmp_path,
        "from urllib.request import urlopen\n\ndef f(url):\n    validate_safe_url(url)\n"
        "    return urlopen(url)\n",
    ) == _FIRES


def test_httpx_default_does_not_follow_redirects(tmp_path: Path) -> None:
    """FP-bait: httpx does not follow redirects unless told to, so no redirect bypass exists."""
    assert _run(
        tmp_path,
        "import httpx\n\nasync def f(url):\n    validate_safe_url(url)\n"
        "    async with httpx.AsyncClient() as c:\n        return await c.get(url)\n",
    ) == []
    assert _run(
        tmp_path,
        "import httpx\n\ndef f(url):\n    validate_safe_url(url)\n    return httpx.get(url)\n",
    ) == []
    assert _run(
        tmp_path,
        "import httpx\n\ndef f(url):\n    validate_safe_url(url)\n"
        "    return httpx.Client(timeout=3).get(url)\n",
    ) == []


def test_httpx_with_follow_redirects_true_still_fires(tmp_path: Path) -> None:
    """Narrowing pin: the httpx default is modelled, an explicit opt-in is not excused."""
    assert _run(
        tmp_path,
        "import httpx\n\ndef f(url):\n    validate_safe_url(url)\n"
        "    return httpx.get(url, follow_redirects=True)\n",
    ) == _FIRES
    assert _run(
        tmp_path,
        "import httpx\n\nasync def f(url):\n    validate_safe_url(url)\n"
        "    async with httpx.AsyncClient(follow_redirects=True) as c:\n        return await c.get(url)\n",
    ) == _FIRES
    assert _run(
        tmp_path,
        "import httpx\n\nasync def f(url):\n    validate_safe_url(url)\n"
        "    async with httpx.AsyncClient() as c:\n        return await c.get(url, follow_redirects=True)\n",
    ) == _FIRES


def test_httpx_api_compatible_client_with_explicit_no_redirects_is_safe(tmp_path: Path) -> None:
    """The review's repro (fastmcp's own `httpx2`, an httpx-API-compatible fetcher imported under
    a different module name): `_is_httpx_ctor`'s `httpx.` prefix match never recognizes it, so its
    explicit, literal `follow_redirects=False` -- unambiguous regardless of which package it
    belongs to -- must be trusted directly."""
    assert _run(
        tmp_path,
        "import httpx2\n\nasync def f(url):\n    validate_safe_url(url)\n"
        "    async with httpx2.AsyncClient(follow_redirects=False) as c:\n"
        "        return await c.get(url)\n",
    ) == []


def test_httpx_api_compatible_client_with_no_explicit_kwarg_still_fires(tmp_path: Path) -> None:
    """Direction traded against: an unrecognized client with NO `follow_redirects` kwarg at all
    must not inherit httpx's own "absent means safe" default -- we don't know this library's
    actual default, so only an explicit `False` counts as evidence."""
    assert _run(
        tmp_path,
        "import httpx2\n\nasync def f(url):\n    validate_safe_url(url)\n"
        "    async with httpx2.AsyncClient() as c:\n        return await c.get(url)\n",
    ) == _FIRES


def test_aiohttp_still_follows_by_default(tmp_path: Path) -> None:
    assert _run(
        tmp_path,
        "import aiohttp\n\nasync def f(url):\n    validate_safe_url(url)\n"
        "    async with aiohttp.ClientSession() as s:\n        return await s.get(url)\n",
    ) == _FIRES


# ── #424 E6 (#1000): the pragma counts only as a real comment, in the file's own grammar ──

_PY_FIRING = (
    "import requests\n\n"
    "def fetch_document(url):\n"
    "    if not validate_safe_url(url):\n"
    "        raise ValueError('unsafe url')\n"
    "    response = requests.get(url)\n"
    "    return response.text\n"
)
_TS_FIRING = (
    "if (validateSafeUrl(url)) {\n"
    "  const res = await fetch(url);\n"
    "}\n"
)


def _ts_run(tmp_path: Path, text: str) -> list[str]:
    (tmp_path / "fetcher.ts").write_text(text, encoding="utf-8")
    prof = mkprofile(tmp_path, features={"typescript"}, python_dirs=["."])
    return [f.rule for f in SsrfRedirectBypassGuard().run(tmp_path, prof)]


# #1064: a UTF-8 BOM survives `read()` and used to fail the parse, so this AST-only guard silently
# skipped the file. Built with chr(): agentsec's own invisible-unicode guard reads this tree.
_BOM = chr(0xFEFF)


def test_a_bom_prefixed_file_is_analysed(tmp_path: Path) -> None:
    assert _run(tmp_path, _BOM + _PY_FIRING) == _FIRES


def test_a_bom_prefixed_safe_file_stays_silent(tmp_path: Path) -> None:
    # FP bait for the widening: the BOM only makes the file readable, it does not make it fire.
    safe = _PY_FIRING.replace("requests.get(url)", "requests.get(url, allow_redirects=False)")
    assert _run(tmp_path, safe) == []  # anti-vacuity: the safe variant is silent without a BOM
    assert _run(tmp_path, _BOM + safe) == []


def test_ssrf_redirect_bypass_pragma_quoted_in_a_string_does_not_suppress(tmp_path: Path) -> None:
    # #424 E6 (#1000): the whole-file opt-out reads the comment-only view, so a Python string quoting
    # the pragma is content; only a real `#` comment (`test_pragma_suppresses_finding`) opts out.
    assert _run(tmp_path, 'HELP = "opt out with # security: allow-ssrf-redirect-bypass"\n' + _PY_FIRING) == _FIRES


@pytest.mark.parametrize("marker", ["//", "#"], ids=["slash-form", "hash-form"])
def test_ssrf_redirect_bypass_pragma_quoted_in_a_string_does_not_suppress_ts(
    tmp_path: Path, marker: str
) -> None:
    # #424 E6 (#1000): D2 widened the pragma to `//`, so a TS string quoting either comment form must
    # stay content (the CLAUDE.md rule-1 test for that widening).
    text = f'const help = "opt out with {marker} security: allow-ssrf-redirect-bypass";\n' + _TS_FIRING
    assert _ts_run(tmp_path, text) == _FIRES


def test_ssrf_redirect_bypass_ts_slash_comment_pragma_suppresses(tmp_path: Path) -> None:
    # #424 E6 (#1000) D2: TS comments are `//`, and the old `#`-only regex never saw one, so the
    # documented opt-out could not be written in a .ts file at all.
    assert _ts_run(tmp_path, _TS_FIRING) == _FIRES
    assert _ts_run(tmp_path, "// security: allow-ssrf-redirect-bypass\n" + _TS_FIRING) == []
