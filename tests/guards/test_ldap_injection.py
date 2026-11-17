from __future__ import annotations

from agentsec.guards.ldap_injection import LdapInjectionGuard
from tests.guards._common import *  # noqa: F401,F403


def test_flags_fstring_filter(tmp_path: Path) -> None:
    (tmp_path / "auth.py").write_text(
        "import ldap\n"
        "def f(conn, username):\n"
        '    return conn.search_s("ou=users", ldap.SCOPE_SUBTREE, f"(uid={username})")\n', encoding="utf-8"
    )
    findings = LdapInjectionGuard().run(tmp_path, _pyprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "ldap-injection/unescaped-search"
    assert findings[0].severity == "medium"

def test_flags_same_line_concatenation(tmp_path: Path) -> None:
    (tmp_path / "auth.py").write_text(
        "import ldap\n"
        "def f(conn, username):\n"
        '    return conn.search_s("ou=users", ldap.SCOPE_SUBTREE, "(uid=" + username + ")")\n', encoding="utf-8"
    )
    assert len(LdapInjectionGuard().run(tmp_path, _pyprof(tmp_path))) == 1

def test_silent_when_escaped(tmp_path: Path) -> None:
    (tmp_path / "auth.py").write_text(
        "import ldap\n"
        "from ldap.filter import escape_filter_chars\n"
        "def f(conn, username):\n"
        '    return conn.search_s("ou=users", ldap.SCOPE_SUBTREE, f"(uid={escape_filter_chars(username)})")\n', encoding="utf-8"
    )
    assert LdapInjectionGuard().run(tmp_path, _pyprof(tmp_path)) == []

def test_silent_on_static_filter(tmp_path: Path) -> None:
    (tmp_path / "auth.py").write_text(
        "import ldap\n"
        "def f(conn):\n"
        '    return conn.search_s("ou=users", ldap.SCOPE_SUBTREE, "(objectClass=*)")\n', encoding="utf-8"
    )
    assert LdapInjectionGuard().run(tmp_path, _pyprof(tmp_path)) == []

def test_pragma_suppresses(tmp_path: Path) -> None:
    (tmp_path / "auth.py").write_text(
        "import ldap\n"
        "def f(conn, username):\n"
        '    return conn.search_s("ou=users", ldap.SCOPE_SUBTREE, f"(uid={username})")  # security: allow-ldap-injection\n', encoding="utf-8"
    )
    assert LdapInjectionGuard().run(tmp_path, _pyprof(tmp_path)) == []

def test_na_without_python() -> None:
    assert LdapInjectionGuard().applies(mkprofile(Path("/tmp"), features={"frontend"})) is False

def test_flags_ldap3_style_search_kwargs(tmp_path: Path) -> None:
    (tmp_path / "auth.py").write_text(
        "def f(conn, username):\n"
        '    conn.search(search_base="ou=users", search_filter=f"(uid={username})")\n', encoding="utf-8"
    )
    findings = LdapInjectionGuard().run(tmp_path, _pyprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "ldap-injection/unescaped-search"

def test_silent_on_bare_re_search(tmp_path: Path) -> None:
    # Real false positive caught against agentsec's own source (detect.py, js_harden.py) during
    # this guard's build: a bare `.search(` collides with the stdlib's re.search(). Only count
    # `.search(` as an LDAP sink when it carries ldap3's own search_base=/search_filter= kwargs.
    (tmp_path / "utils.py").write_text(
        "import re\n"
        "def f(text, pattern):\n"
        "    return re.search(rf'^\\s*{re.escape(pattern)}', text, re.M)\n", encoding="utf-8"
    )
    assert LdapInjectionGuard().run(tmp_path, _pyprof(tmp_path)) == []

def test_silent_on_generic_dot_search(tmp_path: Path) -> None:
    (tmp_path / "cache.py").write_text(
        "def f(cache, key):\n"
        "    return cache.search(f'{key}')\n", encoding="utf-8"
    )
    assert LdapInjectionGuard().run(tmp_path, _pyprof(tmp_path)) == []

def test_flags_multiline_search_call(tmp_path: Path) -> None:
    # #395 H4: a Black/ruff-wrapped multi-line search_s call must still fire.
    (tmp_path / "dir.py").write_text(
        "def lookup(conn, uid):\n"
        "    return conn.search_s(\n"
        "        'ou=people,dc=x',\n"
        "        ldap.SCOPE_SUBTREE,\n"
        "        f'(uid={uid})',\n"
        "    )\n",
        encoding="utf-8",
    )
    findings = LdapInjectionGuard().run(tmp_path, _pyprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "ldap-injection/unescaped-search"

def test_flags_multiline_ldap3_search_call(tmp_path: Path) -> None:
    # #395 H4: ldap3's kwargs may land on a later line of a wrapped call.
    (tmp_path / "dir.py").write_text(
        "def lookup(conn, uid):\n"
        "    return conn.search(\n"
        "        search_base='ou=people,dc=x',\n"
        "        search_filter=f'(uid={uid})',\n"
        "    )\n",
        encoding="utf-8",
    )
    findings = LdapInjectionGuard().run(tmp_path, _pyprof(tmp_path))
    assert len(findings) == 1


# #613: a triple-quoted argument holding an apostrophe used to desync the call splitter, which
# returned None, so the guard skipped the call ("unbalanced parens, don't guess") and missed it.
def test_flags_fstring_filter_after_a_triple_quoted_base_with_an_apostrophe(tmp_path: Path) -> None:
    (tmp_path / "auth.py").write_text(
        "import ldap\n"
        "def f(conn, u):\n"
        "    return conn.search_s('''ou=people's,dc=x''', ldap.SCOPE_SUBTREE, f\"(uid={u})\")\n",
        encoding="utf-8",
    )
    findings = LdapInjectionGuard().run(tmp_path, _pyprof(tmp_path))
    assert [f.rule for f in findings] == ["ldap-injection/unescaped-search"]


def test_silent_on_static_filter_after_a_triple_quoted_base_with_an_apostrophe(tmp_path: Path) -> None:
    # FP-bait for the widening above: the call now splits, and a static filter must stay silent.
    (tmp_path / "auth.py").write_text(
        "import ldap\n"
        "def f(conn):\n"
        "    return conn.search_s('''ou=people's,dc=x''', ldap.SCOPE_SUBTREE, \"(uid=admin)\")\n",
        encoding="utf-8",
    )
    assert LdapInjectionGuard().run(tmp_path, _pyprof(tmp_path)) == []
