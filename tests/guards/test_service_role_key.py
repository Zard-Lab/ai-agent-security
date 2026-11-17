from __future__ import annotations

from agentsec.guards.service_role_key import ServiceRoleKeyGuard
from tests.guards._common import *  # noqa: F401,F403


def test_service_role_flags_client_env(tmp_path: Path) -> None:
    (tmp_path / ".env.example").write_text("VITE_SUPABASE_SERVICE_ROLE_KEY=eyJabc\n", encoding="utf-8")
    findings = ServiceRoleKeyGuard().run(tmp_path, _supabase_prof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "service-role-key/client-env"
    assert findings[0].severity == "critical"

def test_service_role_flags_frontend_reference(tmp_path: Path) -> None:
    fe = tmp_path / "frontend"
    fe.mkdir()
    (fe / "db.ts").write_text(
        "const supabase = createClient(url, import.meta.env.VITE_SUPABASE_SERVICE_ROLE_KEY);\n", encoding="utf-8"
    )
    findings = ServiceRoleKeyGuard().run(tmp_path, _supabase_prof(tmp_path, frontend_dir="frontend"))
    assert len(findings) == 1
    assert findings[0].rule == "service-role-key/reference-in-frontend"

def test_service_role_decodes_jwt_literal(tmp_path: Path) -> None:
    import base64 as b64

    # forge a JWT-shaped literal whose payload says role: service_role
    head = b64.urlsafe_b64encode(b'{"alg":"HS256"}').rstrip(b"=").decode()
    payload = b64.urlsafe_b64encode(b'{"role":"service_role"}').rstrip(b"=").decode()
    fe = tmp_path / "frontend"
    fe.mkdir()
    (fe / "client.ts").write_text(f'const key = "{head}.{payload}.sig0";\n', encoding="utf-8")
    findings = ServiceRoleKeyGuard().run(tmp_path, _supabase_prof(tmp_path, frontend_dir="frontend"))
    assert len(findings) == 1
    assert findings[0].rule == "service-role-key/jwt-literal-in-frontend"

def test_service_role_anon_jwt_not_flagged(tmp_path: Path) -> None:
    import base64 as b64

    head = b64.urlsafe_b64encode(b'{"alg":"HS256"}').rstrip(b"=").decode()
    payload = b64.urlsafe_b64encode(b'{"role":"anon"}').rstrip(b"=").decode()
    fe = tmp_path / "frontend"
    fe.mkdir()
    (fe / "client.ts").write_text(f'const key = "{head}.{payload}.sig0";\n', encoding="utf-8")  # anon key: fine
    assert ServiceRoleKeyGuard().run(tmp_path, _supabase_prof(tmp_path, frontend_dir="frontend")) == []

def test_service_role_backend_use_silent(tmp_path: Path) -> None:
    # Server-side use is the CORRECT place for the key — never flagged.
    (tmp_path / "server.py").write_text(
        'client = create_client(url, os.environ["SUPABASE_SERVICE_ROLE_KEY"])\n', encoding="utf-8"
    )
    assert ServiceRoleKeyGuard().run(tmp_path, _supabase_prof(tmp_path)) == []

def test_service_role_pragma_opt_out(tmp_path: Path) -> None:
    fe = tmp_path / "frontend"
    fe.mkdir()
    (fe / "docs.ts").write_text(
        'const docs = "never put the service_role key here";  // security: allow-service-role\n', encoding="utf-8"
    )
    assert ServiceRoleKeyGuard().run(tmp_path, _supabase_prof(tmp_path, frontend_dir="frontend")) == []

def test_service_role_edge_function_not_flagged(tmp_path: Path) -> None:
    # #423 FP-bait: with no frontend_dir the scan falls back to the whole repo, which used
    # to sweep in supabase/functions/*.ts Deno edge functions — server-side code where
    # SUPABASE_SERVICE_ROLE_KEY is the CORRECT pattern, not a client leak.
    ef = tmp_path / "supabase" / "functions" / "admin-task"
    ef.mkdir(parents=True)
    (ef / "index.ts").write_text(
        'const key = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");  // service_role, server-side\n', encoding="utf-8"
    )
    assert ServiceRoleKeyGuard().run(tmp_path, _supabase_prof(tmp_path)) == []

def test_service_role_whole_repo_fallback_still_flags_frontend(tmp_path: Path) -> None:
    # regression: the whole-repo fallback (no frontend_dir) must still catch a real
    # service_role reference in ordinary client code outside supabase/functions/.
    (tmp_path / "app.ts").write_text("const admin = client(url, SUPABASE_SERVICE_ROLE_KEY);\n", encoding="utf-8")
    findings = ServiceRoleKeyGuard().run(tmp_path, _supabase_prof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "service-role-key/reference-in-frontend"

def test_service_role_not_applicable_without_supabase() -> None:
    prof = mkprofile(Path("/tmp"), features={"python", "frontend"})
    assert ServiceRoleKeyGuard().applies(prof) is False


def test_service_role_silent_on_commented_jwt_literal(tmp_path: Path) -> None:
    # FP-bait (#424): a commented-out service_role JWT literal in frontend code must not fire.
    import base64 as b64
    head = b64.urlsafe_b64encode(b'{"alg":"HS256"}').rstrip(b"=").decode()
    payload = b64.urlsafe_b64encode(b'{"role":"service_role"}').rstrip(b"=").decode()
    fe = tmp_path / "frontend"
    fe.mkdir()
    (fe / "client.ts").write_text(
        f'// const key = "{head}.{payload}.sig0";\n'
        "const x = 1;\n",
        encoding="utf-8",
    )
    assert ServiceRoleKeyGuard().run(tmp_path, _supabase_prof(tmp_path, frontend_dir="frontend")) == []

_SR_JWT = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyb2xlIjoic2VydmljZV9yb2xlIn0.sig"


def test_service_role_jwt_literal_fires_inside_an_edge_function(tmp_path: Path) -> None:
    # Regression (#444 review): the `supabase/functions/` skip was a `continue` at the top of
    # the FILE loop, so it suppressed all three rules including the CRITICAL jwt-literal one.
    # A service_role JWT committed under supabase/functions/ yielded nothing, while the
    # byte-identical literal in app.ts yielded a CRITICAL. A hardcoded key is a committed
    # secret wherever it sits — an edge function is meant to READ it from the environment.
    fn = tmp_path / "supabase" / "functions" / "hello"
    fn.mkdir(parents=True)
    (fn / "index.ts").write_text(f'const k = "{_SR_JWT}";\n', encoding="utf-8")
    (tmp_path / "app.ts").write_text(f'const k = "{_SR_JWT}";\n', encoding="utf-8")
    findings = ServiceRoleKeyGuard().run(tmp_path, _supabase_prof(tmp_path))
    jwt_hits = [f for f in findings if f.rule == "service-role-key/jwt-literal-in-frontend"]
    assert len(jwt_hits) == 2                      # both the edge function AND the frontend
    assert all(f.severity == "critical" for f in jwt_hits)


def test_service_role_env_reference_in_edge_function_stays_silent(tmp_path: Path) -> None:
    # FP-bait, and the case the skip exists for: READING the key from the environment inside a
    # Deno edge function is the correct server-side pattern, not a client leak.
    fn = tmp_path / "supabase" / "functions" / "hello"
    fn.mkdir(parents=True)
    (fn / "index.ts").write_text(
        'const k = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");\n', encoding="utf-8"
    )
    findings = ServiceRoleKeyGuard().run(tmp_path, _supabase_prof(tmp_path))
    assert [f for f in findings if f.rule == "service-role-key/reference-in-frontend"] == []


def test_service_role_pragma_quoted_in_a_string_on_the_line_does_not_opt_out(tmp_path: Path) -> None:
    import base64 as b64

    # #424 E4: the per-line pragma check reads the same-length JS comment-only view, so a string
    # on the finding's own line quoting the pragma is content - only a real `//` comment opts out.
    head = b64.urlsafe_b64encode(b'{"alg":"HS256"}').rstrip(b"=").decode()
    payload = b64.urlsafe_b64encode(b'{"role":"service_role"}').rstrip(b"=").decode()
    fe = tmp_path / "frontend"
    fe.mkdir()
    (fe / "client.ts").write_text(
        f'const key = "{head}.{payload}.sig0"; const help = "opt out with // security: allow-service-role";\n',
        encoding="utf-8",
    )
    findings = ServiceRoleKeyGuard().run(tmp_path, _supabase_prof(tmp_path, frontend_dir="frontend"))
    assert [f.rule for f in findings] == ["service-role-key/jwt-literal-in-frontend"]
