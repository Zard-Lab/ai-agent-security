from __future__ import annotations

from agentsec.guards.secret_in_url_query import SecretInUrlQueryGuard
from tests.guards._common import *  # noqa: F401,F403


def test_secret_in_url_query_fstring_api_key_fires(tmp_path: Path) -> None:
    (tmp_path / "client.py").write_text(
        'requests.get(f"https://api.com/data?api_key={key}")\n',
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python", "fastapi"}, python_dirs=["."])
    findings = SecretInUrlQueryGuard().run(tmp_path, profile)
    assert len(findings) >= 1
    assert findings[0].rule == "secret-in-url-query/secret-in-query-param"
    assert findings[0].severity == "high"

def test_secret_in_url_query_fstring_token_fires(tmp_path: Path) -> None:
    (tmp_path / "api.py").write_text(
        'url = f"https://x.com?token={access_token}&data=1"\n',
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    findings = SecretInUrlQueryGuard().run(tmp_path, profile)
    assert len(findings) >= 1
    assert findings[0].rule == "secret-in-url-query/secret-in-query-param"

def test_secret_in_url_query_params_dict_fires(tmp_path: Path) -> None:
    (tmp_path / "service.py").write_text(
        'requests.get(url, params={"secret": os.environ["KEY"]})\n',
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    findings = SecretInUrlQueryGuard().run(tmp_path, profile)
    assert len(findings) >= 1
    assert findings[0].rule == "secret-in-url-query/secret-in-query-param"

def test_secret_in_url_query_silent_safe_params(tmp_path: Path) -> None:
    (tmp_path / "search.py").write_text(
        'requests.get(f"https://api.com?page={page}&limit={n}")\n',
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    findings = SecretInUrlQueryGuard().run(tmp_path, profile)
    assert findings == []

def test_secret_in_url_query_silent_user_id(tmp_path: Path) -> None:
    (tmp_path / "user.py").write_text(
        'url = f"https://x.com?user_id={uid}"\n',
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    findings = SecretInUrlQueryGuard().run(tmp_path, profile)
    assert findings == []

def test_secret_in_url_query_pragma_silences(tmp_path: Path) -> None:
    content = (
        'requests.get(f"https://api.com/data?api_key={key}")\n'
        "# security: allow-secret-in-url-query\n"
    )
    (tmp_path / "client.py").write_text(content, encoding="utf-8")
    profile = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    findings = SecretInUrlQueryGuard().run(tmp_path, profile)
    assert findings == []

def test_secret_in_url_query_applies_gate(tmp_path: Path) -> None:
    profile = mkprofile(tmp_path, features={"javascript", "react"}, python_dirs=["."])
    guard = SecretInUrlQueryGuard()
    assert guard.applies(profile) is False

def test_secret_in_url_query_applies_with_python(tmp_path: Path) -> None:
    profile = mkprofile(tmp_path, features={"python", "fastapi"}, python_dirs=["."])
    guard = SecretInUrlQueryGuard()
    assert guard.applies(profile) is True

def test_secret_in_url_query_flags_typed_default_query_param(tmp_path: Path) -> None:
    (tmp_path / "routes.py").write_text(
        "@router.get('/login')\n"
        "def login(password: str = Query(...)):\n"
        "    ...\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python", "fastapi"}, python_dirs=["."])
    findings = SecretInUrlQueryGuard().run(tmp_path, profile)
    assert len(findings) >= 1
    assert findings[0].rule == "secret-in-url-query/secret-query-param-declared"
    assert findings[0].severity == "high"

def test_secret_in_url_query_flags_annotated_query_param(tmp_path: Path) -> None:
    # #395 M8: the modern `Annotated[str, Query(...)]` idiom (Query inside the type annotation,
    # no `= Query(` default) must fire too.
    (tmp_path / "routes.py").write_text(
        "@router.get('/login')\n"
        "def login(password: Annotated[str, Query()] = ...):\n"
        "    ...\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python", "fastapi"}, python_dirs=["."])
    findings = SecretInUrlQueryGuard().run(tmp_path, profile)
    assert len(findings) >= 1
    assert findings[0].rule == "secret-in-url-query/secret-query-param-declared"
    assert findings[0].severity == "high"

def test_secret_in_url_query_flags_bare_query_param(tmp_path: Path) -> None:
    (tmp_path / "routes.py").write_text(
        "def reset(api_key = Query(None)):\n"
        "    ...\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python", "fastapi"}, python_dirs=["."])
    findings = SecretInUrlQueryGuard().run(tmp_path, profile)
    assert len(findings) >= 1
    assert findings[0].rule == "secret-in-url-query/secret-query-param-declared"

def test_secret_in_url_query_silent_safe_query_param(tmp_path: Path) -> None:
    (tmp_path / "routes.py").write_text(
        "@router.get('/search')\n"
        "def search(page: int = Query(1), limit: int = Query(20)):\n"
        "    ...\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python", "fastapi"}, python_dirs=["."])
    findings = SecretInUrlQueryGuard().run(tmp_path, profile)
    assert findings == []

def test_secret_in_url_query_no_fp_on_substring_param_names(tmp_path: Path) -> None:
    # #395 review Critical: the Query-param rule matched secret stems as bare substrings, so
    # ordinary names (`author`⊃auth, `cache_key`/`sort_key`⊃key, `passthrough`⊃pass) fired HIGH.
    # Boundaried stems (+ dropping bare `key`) must silence all of them.
    (tmp_path / "routes.py").write_text(
        "@router.get('/list')\n"
        "def list_items(author: str = Query(None), cache_key: str = Query(''), "
        "sort_key: str = Query('name'), passthrough: bool = Query(False)):\n"
        "    ...\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python", "fastapi"}, python_dirs=["."])
    assert SecretInUrlQueryGuard().run(tmp_path, profile) == []


def test_secret_in_url_query_still_fires_on_compound_secret_params(tmp_path: Path) -> None:
    # true positives with a secret stem as a real segment must still fire
    (tmp_path / "routes.py").write_text(
        "def ep(auth_token: str = Query(None), my_secret: str = Query(''), "
        "credentials: str = Query('')):\n    ...\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python", "fastapi"}, python_dirs=["."])
    assert len(SecretInUrlQueryGuard().run(tmp_path, profile)) >= 1


def test_secret_in_url_query_flags_multiple_lines(tmp_path: Path) -> None:
    # Regression guard for a pre-existing bug: the scan used to `break` out of
    # the whole file after the first match, silently missing every later line.
    (tmp_path / "client.py").write_text(
        'requests.get(f"https://api.com/data?api_key={key}")\n'
        'requests.get(f"https://x.com?token={access_token}")\n',
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    findings = SecretInUrlQueryGuard().run(tmp_path, profile)
    assert len(findings) == 2


# --- Express receiving side (codeql js/sensitive-get-query) ---

def test_secret_in_url_query_applies_on_express() -> None:
    assert SecretInUrlQueryGuard().applies(mkprofile(Path("/tmp"), features={"express"})) is True


def test_secret_in_url_query_js_flags_dot_form(tmp_path: Path) -> None:
    (tmp_path / "routes.js").write_text(
        "app.get('/login', (req, res) => {\n  const pw = req.query.password;\n});\n",
        encoding="utf-8",
    )
    findings = SecretInUrlQueryGuard().run(tmp_path, mkprofile(tmp_path, features={"express"}))
    assert len(findings) == 1
    assert findings[0].rule == "secret-in-url-query/secret-query-param-declared"
    assert findings[0].severity == "high"


def test_secret_in_url_query_js_flags_bracket_form(tmp_path: Path) -> None:
    (tmp_path / "routes.js").write_text("const k = req.query['api_key'];\n", encoding="utf-8")
    findings = SecretInUrlQueryGuard().run(tmp_path, mkprofile(tmp_path, features={"express"}))
    assert len(findings) == 1
    assert findings[0].rule == "secret-in-url-query/secret-query-param-declared"


def test_secret_in_url_query_js_flags_compound_secret_name(tmp_path: Path) -> None:
    (tmp_path / "routes.js").write_text("const at = req.query.auth_token;\n", encoding="utf-8")
    findings = SecretInUrlQueryGuard().run(tmp_path, mkprofile(tmp_path, features={"express"}))
    assert len(findings) == 1


def test_secret_in_url_query_js_silent_on_non_secret_param(tmp_path: Path) -> None:
    (tmp_path / "routes.js").write_text("const id = req.query.id;\n", encoding="utf-8")
    assert SecretInUrlQueryGuard().run(tmp_path, mkprofile(tmp_path, features={"express"})) == []


def test_secret_in_url_query_js_silent_on_nonproduct_path(tmp_path: Path) -> None:
    # M3 (the PR #905 review): scope the Express scan to product code, matching
    # this PR's own sibling insecure_cookies.py.
    d = tmp_path / "examples"
    d.mkdir()
    (d / "routes.js").write_text(
        "app.get('/login', (req, res) => {\n  const pw = req.query.password;\n});\n",
        encoding="utf-8",
    )
    assert SecretInUrlQueryGuard().run(tmp_path, mkprofile(tmp_path, features={"express"})) == []


def test_secret_in_url_query_js_silent_on_cache_key(tmp_path: Path) -> None:
    # FP-bait: bare "key" is deliberately excluded from the standalone stem list — cache_key/
    # sort_key/foreign_key are ordinary identifiers, same rationale as the Python side.
    (tmp_path / "routes.js").write_text("const ck = req.query.cache_key;\n", encoding="utf-8")
    assert SecretInUrlQueryGuard().run(tmp_path, mkprofile(tmp_path, features={"express"})) == []


def test_secret_in_url_query_js_pragma_opt_out(tmp_path: Path) -> None:
    (tmp_path / "routes.js").write_text(
        "const pw = req.query.password;  // security: allow-secret-in-url-query\n",
        encoding="utf-8",
    )
    assert SecretInUrlQueryGuard().run(tmp_path, mkprofile(tmp_path, features={"express"})) == []

