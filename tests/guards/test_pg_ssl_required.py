from __future__ import annotations

from agentsec.guards.pg_ssl_required import PgSslRequiredGuard
from tests.guards._common import *  # noqa: F401,F403


def test_pg_ssl_required_flags_remote_dsn(tmp_path: Path) -> None:
    (tmp_path / "config.py").write_text(
        'DATABASE_URL = "postgresql://app:pw@db.example.com:5432/app"\n', encoding="utf-8"
    )
    findings = PgSslRequiredGuard().run(tmp_path, _pgprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "pg-ssl-required/no-sslmode"
    assert findings[0].severity == "medium"

def test_pg_ssl_required_flags_env_file(tmp_path: Path) -> None:
    (tmp_path / ".env").write_text(
        "DATABASE_URL=postgres://app:pw@db.example.com:5432/app\n", encoding="utf-8"
    )
    assert len(PgSslRequiredGuard().run(tmp_path, _pgprof(tmp_path))) == 1

def test_pg_ssl_required_passes_with_sslmode(tmp_path: Path) -> None:
    (tmp_path / "config.py").write_text(
        'DATABASE_URL = "postgresql://app:pw@db.example.com:5432/app?sslmode=require"\n', encoding="utf-8"
    )
    assert PgSslRequiredGuard().run(tmp_path, _pgprof(tmp_path)) == []

def test_pg_ssl_required_ignores_localhost(tmp_path: Path) -> None:
    (tmp_path / "config.py").write_text(
        'DATABASE_URL = "postgresql://app:pw@localhost:5432/app"\n'
        'OTHER = "postgresql://app:pw@127.0.0.1:5432/app"\n', encoding="utf-8"
    )
    assert PgSslRequiredGuard().run(tmp_path, _pgprof(tmp_path)) == []

def test_pg_ssl_required_ignores_compose_service_host(tmp_path: Path) -> None:
    # backlog #4: a bare single-label host is a Docker-compose service name reached on the internal
    # bridge network (no external TLS applicable) — must not fire (was 2 FPs on a RAG app).
    (tmp_path / "config.py").write_text(
        'DATABASE_URL = "postgresql://app:pw@postgres:5432/app"\n'
        'ALT = "postgres://app:pw@db/app"\n', encoding="utf-8"  # bare host, no port
    )
    assert PgSslRequiredGuard().run(tmp_path, _pgprof(tmp_path)) == []

def test_pg_ssl_required_dotted_host_still_fires(tmp_path: Path) -> None:
    # ...but a dotted external host is a real remote DSN and MUST still fire (no FN).
    (tmp_path / "config.py").write_text(
        'DATABASE_URL = "postgresql://app:pw@db.internal.example.com:5432/app"\n', encoding="utf-8"
    )
    rules = [f.rule for f in PgSslRequiredGuard().run(tmp_path, _pgprof(tmp_path))]
    assert "pg-ssl-required/no-sslmode" in rules

def test_pg_ssl_required_ipv6_external_host_still_fires(tmp_path: Path) -> None:
    # #471 review: the host exemption is host-ANCHORED — a bracketed external IPv6 host is external
    # (not a bare service name) and MUST still fire (was a false negative under the loose regex).
    (tmp_path / "config.py").write_text(
        'DATABASE_URL = "postgresql://app:pw@[2001:db8::1]:5432/app"\n', encoding="utf-8"
    )
    rules = [f.rule for f in PgSslRequiredGuard().run(tmp_path, _pgprof(tmp_path))]
    assert "pg-ssl-required/no-sslmode" in rules

def test_pg_ssl_required_at_in_password_does_not_fool_host_check(tmp_path: Path) -> None:
    # #471 review: an unescaped '@' in the password must not make a dotted external host look bare —
    # the host is read after the LAST '@' in the authority, so this still fires.
    (tmp_path / "config.py").write_text(
        'DATABASE_URL = "postgresql://user:weird@word:pass@db.example.com:5432/mydb"\n', encoding="utf-8"
    )
    rules = [f.rule for f in PgSslRequiredGuard().run(tmp_path, _pgprof(tmp_path))]
    assert "pg-ssl-required/no-sslmode" in rules

def test_pg_ssl_required_pragma_opt_out(tmp_path: Path) -> None:
    (tmp_path / "config.py").write_text(
        'DATABASE_URL = "postgresql://app:pw@db.example.com:5432/app"  # security: allow-no-pg-ssl\n', encoding="utf-8"
    )
    assert PgSslRequiredGuard().run(tmp_path, _pgprof(tmp_path)) == []

def test_pg_ssl_required_ignores_credential_and_path_less_localhost(tmp_path: Path) -> None:
    # #423 FP-bait: the localhost exemption must also match a credential-less DSN and a
    # path-less one (no trailing :port//db) — both are localhost, no network SSL needed.
    (tmp_path / "cfg.py").write_text(
        'A = "postgresql://localhost:5432/mydb"\n'   # no user:pass@
        'B = "postgresql://u:p@localhost"\n',        # no :port and no /db
        encoding="utf-8",
    )
    p = mkprofile(tmp_path, features={"postgres"}, python_dirs=["."])
    assert PgSslRequiredGuard().run(tmp_path, p) == []

def test_pg_ssl_required_applies_on_supabase_not_bare_python() -> None:
    assert PgSslRequiredGuard().applies(mkprofile(Path("/tmp"), features={"supabase"})) is True
    assert PgSslRequiredGuard().applies(mkprofile(Path("/tmp"), features={"python"})) is False



def test_pg_ssl_password_containing_url_delimiters_still_fires(tmp_path: Path) -> None:
    # Regression (#471 review, HIGH): the authority was taken as "everything up to the first
    # /?#", but a raw password routinely contains those — base64 secrets contain `/` all the
    # time. The authority was truncated BEFORE the `@`, leaving a fragment of the password as
    # the "host"; with no dot in it the DSN was classified internal and the finding silenced.
    # 73 of 200 randomly generated 32-char base64 passwords went silent that way.
    from agentsec.guards.pg_ssl_required import _is_internal_host

    for dsn in (
        "postgresql://user:pa/ss@db.example.com:5432/app?sslmode=disable",
        "postgresql://user:pa?ss@db.example.com:5432/app",
        "postgresql://user:pa#ss@db.example.com:5432/app",
        "postgresql://user:p@ssw0rd@db.example.com/app",
    ):
        assert _is_internal_host(dsn) is False, dsn

    # `is False` alone cannot tell a CORRECT parse from a failed one — both report "not internal"
    # — so the unescaped-`@`-in-password case gets its resolved host pinned too. Without this,
    # swapping the userinfo scan from `rfind` to `find` changed nothing any test could see
    # (verified by sabotage). Userinfo runs to the LAST `@` in the authority, per RFC 3986.
    from agentsec.guards.pg_ssl_required import _host_port

    assert _host_port("user:p@ssw0rd@db.example.com/app") == "db.example.com"
    assert _host_port("user:p@ssw0rd@postgres:5432/app") == "postgres:5432"


def test_pg_ssl_query_string_at_does_not_silence_an_external_host(tmp_path: Path) -> None:
    # Regression (#471 review round 2, CRITICAL): `@` candidates were scanned from the last
    # backwards across the WHOLE DSN, so an `@` in the query string won outright. A real external
    # `db.example.com` carrying the ordinary libpq `?application_name=svc@worker` resolved to the
    # host `worker` — dotless, therefore read as a compose service name — and the finding was
    # suppressed entirely. Main fired; the branch did not. An FP tune that silently killed a real
    # detection, which is the direction Rule 1 exists to catch.
    #
    # End-to-end through run(), not just the helper: the helper returning the right string is not
    # the claim that matters, the finding appearing is.
    (tmp_path / "settings.py").write_text(
        'A = "postgresql://user:pass@db.example.com:5432/mydb?application_name=svc@worker"\n'
        'B = "postgresql://user:pass@db.example.com:5432/mydb?options=x@y"\n',
        encoding="utf-8",
    )
    findings = PgSslRequiredGuard().run(tmp_path, mkprofile(tmp_path, features={"python", "sql"}))
    assert len(findings) == 2, "a query-string @ must not exempt a dotted external host"
    assert all(f.rule == "pg-ssl-required/no-sslmode" for f in findings)


def test_pg_ssl_path_at_does_not_silence_an_external_host(tmp_path: Path) -> None:
    # Regression (#471 review round 4, CRITICAL): the authority scan bounded on `?` and `#` but
    # never on `/`, which is the delimiter RFC 3986 puts FIRST. So an `@` in the PATH beat the
    # real userinfo separator exactly as round 1's query `@` did, and the dotless fragment after
    # it was read as a compose service name. `.../tickets@acme-corp` resolved to host `acme-corp`
    # and the DSN went silent. A regression against main, which fires on all three of these.
    #
    # This is the arm no round covered: rounds 1-3 all fixed the `?`/`#` axis and none of them,
    # nor their sabotage tables, ever exercised a path `@`.
    (tmp_path / "settings.py").write_text(
        'A = "postgresql://db.example.com/x@y"\n'
        'B = "postgresql://u:p@db.example.com/x@y"\n'
        'C = "postgresql://prod:S3cr3t@db.prod.example.com:5432/tickets@acme-corp"\n'
        'D = "postgresql://user:p@ss/word@db.example.com/db"\n',
        encoding="utf-8",
    )
    findings = PgSslRequiredGuard().run(tmp_path, mkprofile(tmp_path, features={"python", "sql"}))
    assert len(findings) == 4, "an @ in the path must not exempt a real external host"


def test_pg_ssl_path_at_fires_even_on_an_internal_host(tmp_path: Path) -> None:
    # The disclosed trade-off, asserted rather than left implicit (#471 review round 5). A path `@`
    # is indistinguishable from an authority truncated by a raw delimiter in the password, so it
    # fires even when the host would otherwise be exempt. Documented in the guard design doc; the
    # pragma covers it. Pinning it here because an untested trade-off is exactly how this chain
    # started — a claim in a docstring that no test could contradict.
    (tmp_path / "settings.py").write_text(
        'A = "postgresql://postgres/tickets@acme-corp"\n', encoding="utf-8"
    )
    findings = PgSslRequiredGuard().run(tmp_path, mkprofile(tmp_path, features={"python", "sql"}))
    assert len(findings) == 1, "a path @ is ambiguous and must fire, internal-looking host or not"


def test_pg_ssl_credential_less_internal_host_survives_a_stray_at(tmp_path: Path) -> None:
    # FP-bait for the fail-loud widening (#471 review round 3). The first cut of that check asked
    # "is there an `@` anywhere in the DSN", which is not the same question as "is there userinfo".
    # A credential-less compose DSN carrying an `@` in the query or fragment was read as having
    # userinfo it could not parse, and fired — the guard's own canonical exemption case, killed by
    # the fix that was closing a false negative. Rule 1 recurring inside a Rule 1 fix.
    #
    # `head` (everything before the first `/?#`) parsing as a host[:port] is what settles it: a
    # later `@` then lies in the path, query or fragment, none of which can carry userinfo.
    (tmp_path / "settings.py").write_text(
        'A = "postgresql://postgres:5432/mydb?application_name=svc@worker"\n'
        'B = "postgresql://postgres:5432/mydb#frag@x"\n'
        'C = "postgresql://db/app?options=x@y"\n',
        encoding="utf-8",
    )
    findings = PgSslRequiredGuard().run(tmp_path, mkprofile(tmp_path, features={"python", "sql"}))
    assert findings == [], "a stray @ past the authority must not defeat the internal-host exemption"


def test_pg_ssl_ambiguous_authority_fires_rather_than_suppresses(tmp_path: Path) -> None:
    # The fail-loud direction, asserted rather than assumed. `_host_port` returns None when a DSN
    # carries userinfo but no `@` position yields a parseable host — a password containing a raw
    # `?`/`#` truncates the authority bound. None must reach the user as a FINDING, because this
    # helper decides whether to SUPPRESS: an ambiguous parse resolving to "internal" is the silent
    # failure this whole round was about.
    from agentsec.guards.pg_ssl_required import _host_port

    assert _host_port("user:pa?ss@db.example.com:5432/app") is None
    (tmp_path / "settings.py").write_text(
        'A = "postgresql://user:pa?ss@postgres:5432/app"\n', encoding="utf-8"
    )
    findings = PgSslRequiredGuard().run(tmp_path, mkprofile(tmp_path, features={"python", "sql"}))
    assert len(findings) == 1, "an unparseable authority must fire, not be exempted"


def test_pg_ssl_internal_host_exemption_is_intact(tmp_path: Path) -> None:
    # FP-bait: the exemption the parse exists for must survive — a single-label compose service
    # name is internal, a bracketed IPv6 host is external, and an `@` inside a QUERY string must
    # not be mistaken for the end of the userinfo.
    from agentsec.guards.pg_ssl_required import _host_port, _is_internal_host

    assert _is_internal_host("postgresql://user:pass@postgres:5432/app") is True
    assert _is_internal_host("postgresql://postgres/app") is True
    assert _is_internal_host("postgresql://user:pass@[2001:db8::1]:5432/app") is False

    # The query-`@` arm used a DOTLESS fixture host (`@host`), so it could not discriminate: the
    # parse resolved the host to the query fragment `y`, which is also dotless, and the assertion
    # passed either way. It would have passed against a completely broken parser, and it did pass
    # against one (#471 review round 2). The host here is DOTTED, so resolving to the query
    # fragment flips the result and the arm fails.
    assert _is_internal_host("postgresql://u:p@db.example.com/db?options=x@y") is False
    assert _host_port("u:p@db.example.com/db?options=x@y") == "db.example.com"

    # Still internal when the host genuinely IS a service name and a query `@` is present, so the
    # bound above is not just suppressing the whole query-carrying class.
    assert _is_internal_host("postgresql://u:p@postgres:5432/db?options=x@y") is True
