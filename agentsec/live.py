"""Live scanners for `agentsec live`.

The static guards/runners read files on disk; these drive scanners that need a
**running** target and feed their output into the same `Finding` model the
`--ingest` path uses:

- **OWASP ZAP** baseline DAST against a live URL (via the official Docker image).
- **Supabase Splinter** DB lint against a live Postgres (via `psql`).

Each degrades gracefully — when its tool/target/input is missing it returns a
`LiveResult` with `ran=False` and a human reason, never raising — mirroring how
the deterministic-scanner runners report "not installed".
"""
from __future__ import annotations

import json
import re
import subprocess  # nosec B404 (subprocess orchestrates external scanners; no shell)
import tempfile
import tomllib
import urllib.error
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

from agentsec import net
from agentsec.findings import Finding
from agentsec.ingest import (
    parse_garak,
    parse_jwt_tool,
    parse_promptfoo,
    parse_schemathesis,
    parse_splinter,
    parse_zap,
)
from agentsec.runners.base import child_env, which
from agentsec.targets import classify_host

ZAP_IMAGE = "ghcr.io/zaproxy/zaproxy:stable"
# Schemathesis is invoked from PATH (`st`); pinned only for the doctor/install hint.
SCHEMATHESIS_PIN = "4.21.0"
# Small default wordlist for jwt_tool HMAC cracking (mirrors the donor's list).
JWT_TOOL_WORDLIST = (
    "secret", "changeme", "password", "admin", "test", "default",
    "12345678", "0123456789abcdef",
)

# Pinned Supabase Splinter lint query (Apache-2.0). Pinned to a commit for
# reproducibility; override the source with `--splinter-sql PATH`.
SPLINTER_PIN = "a7f71080ed059de8a7f00addd71ade19b82a4108"
SPLINTER_URL = f"https://raw.githubusercontent.com/supabase/splinter/{SPLINTER_PIN}/splinter.sql"


@dataclass
class LiveResult:
    name: str
    ran: bool
    findings: list[Finding] = field(default_factory=list)
    skip_reason: str = ""


# --- auth bootstrap + reachability (DAST against a seeded non-prod target) ---


def mint_token_cmd(command: str, timeout: int = 60) -> str:
    """Run a shell `command` and return its stdout (trimmed) as a bearer token.

    The generic auth escape hatch: any token-minting recipe (curl + jq, a CLI, a
    login script) works. The command is user-provided and intentionally runs in a
    shell. Never raises — a failure returns ``""`` and the scan proceeds
    unauthenticated (with a note)."""
    try:
        proc = subprocess.run(
            command, shell=True, capture_output=True, text=True,  # noqa: S602  # nosec B602  # nosemgrep
            timeout=timeout, check=False, env=child_env(),
        )
    except (OSError, subprocess.TimeoutExpired):
        return ""
    return proc.stdout.strip()


def mint_supabase_token(
    supabase_url: str, anon_key: str, email: str, password: str, timeout: int = 30
) -> str:
    """Mint a user access token via the Supabase password grant (the first-class
    counterpart of the flagship's ``mint-supabase-token.sh``). POSTs to
    ``/auth/v1/token?grant_type=password`` and returns ``access_token``.

    Never raises; returns ``""`` on any failure. Never logs the password or token."""
    if not (supabase_url and anon_key and email and password):
        return ""
    if not supabase_url.lower().startswith("https://"):
        return ""  # never POST a password over cleartext (B310's real concern)
    url = supabase_url.rstrip("/") + "/auth/v1/token?grant_type=password"
    body = json.dumps({"email": email, "password": password}).encode()
    req = net.Request(
        url, data=body, method="POST",
        headers={"apikey": anon_key, "Content-Type": "application/json"},
    )
    try:
        with net.urlopen(req, timeout=timeout) as r:  # noqa: S310  # nosec B310
            data = json.loads(r.read().decode())
    except (OSError, ValueError):
        return ""
    return str(data.get("access_token") or "") if isinstance(data, dict) else ""


def _reachable(url: str, timeout: int = 10) -> bool:
    """True if `url` answers at all (any HTTP status = reachable). A fast GET probe
    so a down target fails with a clear reason instead of a confusing empty scan.
    Never raises."""
    if urlsplit(url).scheme not in ("http", "https"):
        return False  # reject file:// / custom schemes from a user-supplied URL
    try:
        with net.urlopen(url, timeout=timeout):  # noqa: S310  # nosec B310 (scheme-validated above)
            return True
    except urllib.error.HTTPError:
        return True  # a 4xx/5xx still means the host answered
    except (OSError, ValueError):
        return False


def run_zap(
    target_url: str,
    image: str = ZAP_IMAGE,
    timeout: int = 900,
    active: bool = False,
    openapi_url: str = "",
    auth_header: str = "",
    network_host: bool = False,
    allow_remote: bool = False,
    rules_tsv: str = "",
) -> LiveResult:
    """Run a ZAP scan against a live target and parse the JSON report.

    Two modes (both need Docker; the script exits non-zero when it finds alerts —
    expected, not a failure; only a missing/unparseable report is):
    - **passive baseline** (default) — `zap-baseline.py` spiders + observes only.
    - **active API scan** (`active=True`) — `zap-api-scan.py` feeds ZAP the OpenAPI
      spec and **sends real attack payloads** (SQLi/XSS/traversal/…). Intrusive:
      run only against a stack you own, in a quiet window. `auth_header` (a bearer
      token) is injected into every request via ZAP's replacer add-on.

    Safety: the active scan (and its OpenAPI-spec import, which makes ZAP call every
    endpoint incl. mutating POSTs) is **hard-refused against a remote host** unless
    `allow_remote` is set — passive baseline is left runnable anywhere.

    Networking: by default the container joins the bridge network with
    ``--add-host=host.docker.internal:host-gateway``, so a host-published port is
    reached as ``http://host.docker.internal:PORT``. With ``network_host=True`` the
    container shares the host's network namespace (``--network=host``) and reaches
    ``http://127.0.0.1:PORT`` directly — simpler, but **Linux-only** (a no-op on
    Docker Desktop for macOS/Windows). Mirrors the production `run-zap.sh` recipe.
    """
    if active and not allow_remote and any(
        u and classify_host(u) == "remote" for u in (target_url, openapi_url)
    ):
        return LiveResult(
            "zap", False,
            skip_reason="remote target — active scan refused without --allow-remote-target",
        )
    if not which("docker"):
        return LiveResult("zap", False, skip_reason="docker not installed")
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as d:
        net_mode = "--network=host" if network_host else "--add-host=host.docker.internal:host-gateway"
        base = ["docker", "run", "--rm", net_mode, "-v", f"{d}:/zap/wrk:rw", image]
        if active:
            spec = openapi_url or target_url
            cmd = base + ["zap-api-scan.py", "-t", spec, "-f", "openapi", "-J", "zap.json"]
            if auth_header:
                # replacer add-on: inject Authorization into every outbound request
                cmd += ["-z", f"replacer.full_list(0).description=auth;"
                              f"replacer.full_list(0).enabled=true;"
                              f"replacer.full_list(0).matchtype=REQ_HEADER;"
                              f"replacer.full_list(0).matchstr=Authorization;"
                              f"replacer.full_list(0).replacement=Bearer {auth_header}"]
        else:
            cmd = base + ["zap-baseline.py", "-t", target_url, "-J", "zap.json"]
        # ZAP rule-config TSV (`-c`): suppress known-noise alerts per plugin/URL. The
        # file is copied into the mounted /zap/wrk dir, where the scripts resolve `-c`.
        if rules_tsv and Path(rules_tsv).is_file():
            # Read + write as UTF-8 so a non-ASCII rule comment doesn't corrupt under a
            # cp1252 default (Windows) — mirrors the repo-wide UTF-8 file-IO convention.
            (Path(d) / "rules.tsv").write_text(
                Path(rules_tsv).read_text(encoding="utf-8", errors="replace"), encoding="utf-8"
            )
            cmd += ["-c", "rules.tsv"]
        try:
            subprocess.run(cmd, capture_output=True, timeout=timeout, check=False, env=child_env())  # nosec B603
        except (OSError, subprocess.TimeoutExpired) as e:
            return LiveResult("zap", False, skip_reason=f"docker/zap run failed: {e}")
        report = Path(d) / "zap.json"
        if not report.is_file():
            return LiveResult("zap", False, skip_reason="zap produced no report (target unreachable?)")
        try:
            data = json.loads(report.read_text(encoding="utf-8", errors="replace"))
        except (OSError, json.JSONDecodeError) as e:
            return LiveResult("zap", False, skip_reason=f"zap report unreadable: {e}")
    return LiveResult("zap", True, findings=parse_zap(data))


def _resolve_splinter_sql(splinter_sql: str | None, allow_fetch: bool) -> tuple[str | None, str]:
    """Return (sql_text, error). Reads `--splinter-sql` if given, else fetches the
    pinned copy (when `allow_fetch`), else explains why it can't."""
    if splinter_sql:
        p = Path(splinter_sql)
        if not p.is_file():
            return None, f"--splinter-sql not found: {p}"
        try:
            return p.read_text(encoding="utf-8", errors="replace"), ""
        except OSError as e:
            return None, f"--splinter-sql unreadable: {e}"
    if not allow_fetch:
        return None, "no --splinter-sql and fetch disabled"
    try:
        with net.urlopen(SPLINTER_URL, timeout=30) as r:  # noqa: S310  # nosec B310
            return r.read().decode(), ""
    except (OSError, ValueError) as e:
        return None, f"could not fetch pinned splinter.sql: {e}"


_DB_SCHEMAS_RE = re.compile(r"^[A-Za-z0-9_,]+$")


def _sanitize_db_schemas(db_schemas: str) -> str:
    """Validate the comma-list before interpolating it into SQL (injection guard).

    Falls back to `public` on anything unexpected (empty, spaces-only, or
    out-of-charset)."""
    cleaned = db_schemas.replace(" ", "")
    return cleaned if cleaned and _DB_SCHEMAS_RE.match(cleaned) else "public"


def _wrap_splinter(sql: str, db_schemas: str = "public") -> str:
    """Wrap Splinter's `set local search_path=''` + UNION-ALL query into one that
    emits a JSON array (the shape `parse_splinter` ingests). `pgrst.db_schemas`
    is set to the exposed-schema list so the Data-API RLS / SECURITY DEFINER lints
    fire on a direct psql connection — not just for `public`. Run as the migration
    role this GUC is otherwise empty, silently zeroing those lints (the flagship
    blind spot; see docs/knowledge/exposed-schema-rls-blind-spot.md)."""
    body = "\n".join(sql.splitlines()[1:])  # drop splinter's own `set local search_path` line
    schemas = _sanitize_db_schemas(db_schemas)
    return (
        f"set pgrst.db_schemas = '{schemas}';\n"  # nosec B608 (sanitized schema list; pinned Splinter SQL)
        "select coalesce(json_agg(row_to_json(t)),'[]'::json) from (\n"
        f"{body}\n) t;\n"
    )


def run_splinter(
    db_url: str,
    splinter_sql: str | None = None,
    allow_fetch: bool = True,
    timeout: int = 120,
    db_schemas: str = "public",
    allow_remote: bool = False,
) -> LiveResult:
    """Run Supabase Splinter against `db_url` (a Postgres DSN) and parse the lints.

    Needs `psql` and the Splinter lint SQL (`--splinter-sql` or the pinned fetch).
    `db_schemas` is the comma-list of PostgREST-exposed schemas to lint (default
    `public`); pass the app's real exposed list so the exposed-schema lints fire.

    Splinter is read-only, but a remote `db_url` is still refused unless
    `allow_remote` is set (don't lint production by accident). A fast `SELECT 1`
    pre-flight turns an unreachable/bad DSN into a clean skip reason rather than a
    confusing empty result from the main query.
    """
    if classify_host(db_url) == "remote" and not allow_remote:
        return LiveResult(
            "splinter", False,
            skip_reason="remote database — refused without --allow-remote-db",
        )
    if not which("psql"):
        return LiveResult("splinter", False, skip_reason="psql not installed")
    sql, err = _resolve_splinter_sql(splinter_sql, allow_fetch)
    if sql is None:
        return LiveResult("splinter", False, skip_reason=err)
    # pre-flight: a fast SELECT 1 turns an unreachable/bad DSN into a clean skip
    # reason rather than a confusing empty result from the main lint query.
    try:
        pre = subprocess.run(  # nosec B603 B607 (fixed argv, no shell; tool on PATH)
            ["psql", db_url, "-Atc", "select 1"],
            capture_output=True, text=True, timeout=min(timeout, 30), check=False, env=child_env(),
        )
    except (OSError, subprocess.TimeoutExpired) as e:
        return LiveResult("splinter", False, skip_reason=f"db pre-flight failed: {e}")
    if pre.returncode != 0 or "1" not in pre.stdout:
        why = pre.stderr.strip().splitlines()[-1] if pre.stderr.strip() else "no response"
        return LiveResult("splinter", False, skip_reason=f"database unreachable ({why[:120]})")
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as d:
        wrap = Path(d) / "wrapped.sql"
        wrap.write_text(_wrap_splinter(sql, db_schemas), encoding="utf-8")
        try:
            proc = subprocess.run(  # nosec B603 B607 (fixed argv, no shell; tool on PATH)
                ["psql", db_url, "-At", "-f", str(wrap)],
                capture_output=True, text=True, timeout=timeout, check=False, env=child_env(),
            )
        except (OSError, subprocess.TimeoutExpired) as e:
            return LiveResult("splinter", False, skip_reason=f"psql run failed: {e}")
    # keep only the JSON array line (drops psql's leading `SET` tag)
    line = next((ln for ln in proc.stdout.splitlines() if ln.startswith("[")), "")
    if not line:
        why = proc.stderr.strip().splitlines()[-1] if proc.stderr.strip() else "no JSON output"
        return LiveResult("splinter", False, skip_reason=f"splinter produced no findings ({why[:120]})")
    try:
        data = json.loads(line)
    except json.JSONDecodeError as e:
        return LiveResult("splinter", False, skip_reason=f"splinter JSON parse error: {e}")
    return LiveResult("splinter", True, findings=parse_splinter(data))


def _load_schemathesis_skips(path: str | None) -> list[str]:
    """Read endpoint patterns to exclude from a TOML skip file → `--exclude-path` args.

    LLM/RAG endpoints are slow and token-expensive to fuzz, so excluding them keeps
    DAST affordable. Accepts the donor's `[skip]` table (string array under any key)
    or a top-level `exclude_path = [...]`. Missing/malformed → [] (never fails).
    """
    if not path:
        return []
    p = Path(path)
    if not p.is_file():
        return []
    try:
        data = tomllib.loads(p.read_text(encoding="utf-8", errors="replace"))
    except (OSError, tomllib.TOMLDecodeError):
        return []
    patterns: list[str] = []
    top = data.get("exclude_path")
    if isinstance(top, list):
        patterns += [str(x) for x in top]
    skip = data.get("skip")
    if isinstance(skip, dict):
        for v in skip.values():
            if isinstance(v, list):
                patterns += [str(x) for x in v]
    elif isinstance(skip, list):
        patterns += [str(x) for x in skip]
    return patterns


def run_schemathesis(  # nosec B107 (empty-string default, not a secret)
    base_url: str,
    token: str = "",
    origin: str = "",
    max_examples: int = 30,
    skip_paths: list[str] | None = None,
    timeout: int = 900,
    allow_remote: bool = False,
) -> LiveResult:
    """Run Schemathesis OpenAPI fuzzing against a live API and parse the JUnit report.

    Needs the `st` binary (`uv tool install schemathesis==4.21.0`). `st` exits
    non-zero when it finds violations — expected; only a missing report is a failure.

    Fuzzing sends generated requests (incl. mutating POST/PUT/DELETE) to every
    endpoint, so a remote `base_url` is **hard-refused** unless `allow_remote` is set.
    """
    if classify_host(base_url) == "remote" and not allow_remote:
        return LiveResult(
            "schemathesis", False,
            skip_reason="remote target — fuzzing refused without --allow-remote-target",
        )
    if not which("st"):
        return LiveResult("schemathesis", False, skip_reason="schemathesis (st) not installed")
    # Health-check / OpenAPI auto-discovery: confirm the spec is actually served before
    # a long fuzzing run, so a down target is a clear skip — not a confusing empty pass.
    openapi = f"{base_url.rstrip('/')}/openapi.json"
    if not _reachable(openapi):
        return LiveResult("schemathesis", False, skip_reason=f"OpenAPI spec unreachable at {openapi}")
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as d:
        report = Path(d) / "schemathesis-junit.xml"
        cmd = [
            "st", "run", openapi,
            "--checks", "all",
            "--phases", "examples,coverage,fuzzing,stateful",
            "--max-examples", str(max_examples),
            "--exclude-deprecated",
        ]
        if token:
            cmd += ["--header", f"Authorization: Bearer {token}"]
        if origin:
            cmd += ["--header", f"Origin: {origin}"]
        for pat in skip_paths or []:
            cmd += ["--exclude-path", pat]
        cmd += ["--report", "junit", "--report-junit-path", str(report)]
        try:
            subprocess.run(cmd, capture_output=True, timeout=timeout, check=False, env=child_env())  # nosec B603
        except (OSError, subprocess.TimeoutExpired) as e:
            return LiveResult("schemathesis", False, skip_reason=f"schemathesis run failed: {e}")
        if not report.is_file():
            return LiveResult("schemathesis", False,
                              skip_reason="schemathesis produced no report (target unreachable?)")
        try:
            xml = report.read_text(encoding="utf-8", errors="replace")
        except OSError as e:
            return LiveResult("schemathesis", False, skip_reason=f"schemathesis report unreadable: {e}")
    return LiveResult("schemathesis", True, findings=parse_schemathesis(xml))


def run_jwt_tool(  # nosec B107 (empty-string default, not a secret)
    target_url: str,
    token: str = "",
    canary: str = "",
    wordlist: tuple[str, ...] | None = None,
    timeout: int = 300,
) -> LiveResult:
    """Run a generic single-target jwt_tool scan and classify killer findings.

    Needs `jwt_tool` on PATH (https://github.com/ticarpi/jwt_tool). The donor's
    two-stage widget-token/canary flow is app-specific (token minting, two endpoints)
    — left as a future extension; this runs the generic all-tests scan + optional
    HMAC-crack pass. Never raises.
    """
    if not which("jwt_tool"):
        return LiveResult("jwt-tool", False,
                          skip_reason="jwt_tool not installed (https://github.com/ticarpi/jwt_tool)")
    cmd = ["jwt_tool", "-t", target_url, "-np", "-M", "at"]
    if token:
        cmd += ["-rh", f"Authorization: Bearer {token}"]
    if canary:
        cmd += ["-cv", canary]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False, env=child_env())  # nosec B603
        out = proc.stdout + proc.stderr
        if token:
            with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as d:
                wl = Path(d) / "wordlist.txt"
                wl.write_text("\n".join(wordlist or JWT_TOOL_WORDLIST) + "\n", encoding="utf-8")
                crack = subprocess.run(  # nosec B603 B607 (fixed argv, no shell; tool on PATH)
                    ["jwt_tool", token, "-np", "-C", "-d", str(wl)],
                    capture_output=True, text=True, timeout=timeout, check=False, env=child_env(),
                )
                out += crack.stdout + crack.stderr
    except (OSError, subprocess.TimeoutExpired) as e:
        return LiveResult("jwt-tool", False, skip_reason=f"jwt_tool run failed: {e}")
    return LiveResult("jwt-tool", True, findings=parse_jwt_tool(out))


def run_garak(
    target_url: str,
    probes: str = "promptinject,latentinjection",
    generations: int = 1,
    timeout: int = 600,
) -> LiveResult:
    """Run GARAK against a live LLM REST endpoint and parse its report JSONL.

    GARAK ("nmap of LLMs") probes a *running* model for jailbreaks, prompt injection,
    and data leaks — the dynamic complement to the static guards. Needs `garak` on
    PATH (`pipx install garak`). Never raises; a missing binary/target degrades to a
    skip.

    The endpoint URI is passed via a generated `-G` JSON config, NOT `--model_name`:
    since garak 0.13.1 `--model_name` is deprecated and no longer sets the REST URI
    (garak then aborts with "No REST endpoint URI definition found"). The default
    REST contract here POSTs the raw prompt (`$INPUT`) as the request body and treats
    the whole text response as the model output (`response_json: false`) — a plain
    "prompt in, text out" adapter is all a target needs to expose. Requires garak
    >= 0.13.1 (for `--target_type`); the `*.report.jsonl` schema is validated against
    representative output — confirm against your installed GARAK version.

    `probes` and `generations` are COST controls. A real RAG/agent target answers
    each prompt with a full (slow, paid) LLM turn, and probe modules carry ~256
    prompts each, so the full set at garak's default 5 generations is thousands of
    calls / many hours. Defaults here are deliberately bounded: a focused probe set
    (NB: `xss` was removed — it is not a valid probe in garak 0.15.x; its attacks
    live under `latentinjection`) and `generations=1`. Raise either for deeper
    coverage at proportionally higher cost.
    """
    if not which("garak"):
        return LiveResult("garak", False, skip_reason="garak not installed (pipx install garak)")
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as d:
        prefix = str(Path(d) / "run")
        rest_config = Path(d) / "garak_rest.json"
        rest_config.write_text(json.dumps({
            "rest": {
                "RestGenerator": {
                    "name": "agentsec-target",
                    "uri": target_url,
                    "method": "post",
                    "req_template": "$INPUT",
                    "response_json": False,
                    # garak's REST generator defaults to a 20s read timeout; a real
                    # RAG/agent target routinely answers slower than that, and a
                    # single ReadTimeout aborts the ENTIRE garak run. Give it room.
                    "request_timeout": 90,
                }
            }
        }), encoding="utf-8")
        cmd = ["garak", "--target_type", "rest", "-G", str(rest_config),
               "--probes", probes, "--generations", str(generations),
               "--report_prefix", prefix]
        try:
            subprocess.run(cmd, capture_output=True, timeout=timeout, check=False, env=child_env())  # nosec B603
        except (OSError, subprocess.TimeoutExpired) as e:
            return LiveResult("garak", False, skip_reason=f"garak run failed: {e}")
        report = Path(f"{prefix}.report.jsonl")  # security: allow-path-traversal
        if not report.is_file():
            return LiveResult("garak", False, skip_reason="garak produced no report (target unreachable?)")
        try:
            raw = report.read_text(encoding="utf-8", errors="replace")
        except OSError as e:
            return LiveResult("garak", False, skip_reason=f"garak report unreadable: {e}")
    return LiveResult("garak", True, findings=parse_garak(raw))


def run_promptfoo(config_path: str, timeout: int = 600) -> LiveResult:
    """Run promptfoo's declarative eval/red-team suite against the app's LLM and parse
    the JSON results. Needs `promptfoo` on PATH (`npm install -g promptfoo`) and a
    `promptfooconfig.yaml`. A failed assertion (prompt firewall/sanitizer regressed)
    becomes a finding. Never raises; missing binary/config degrades to a skip.
    """
    if not which("promptfoo"):
        return LiveResult("promptfoo", False,
                          skip_reason="promptfoo not installed (npm install -g promptfoo)")
    cfg = Path(config_path)
    if not cfg.is_file():
        return LiveResult("promptfoo", False, skip_reason=f"promptfoo config not found: {cfg}")
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as d:
        out_json = Path(d) / "results.json"
        cmd = ["promptfoo", "eval", "-c", str(cfg), "-o", str(out_json), "--no-progress-bar"]
        try:
            subprocess.run(cmd, capture_output=True, timeout=timeout, check=False, env=child_env())  # nosec B603
        except (OSError, subprocess.TimeoutExpired) as e:
            return LiveResult("promptfoo", False, skip_reason=f"promptfoo run failed: {e}")
        if not out_json.is_file():
            return LiveResult("promptfoo", False,
                              skip_reason="promptfoo produced no report (target unreachable?)")
        try:
            data = json.loads(out_json.read_text(encoding="utf-8", errors="replace"))
        except (OSError, json.JSONDecodeError) as e:
            return LiveResult("promptfoo", False, skip_reason=f"promptfoo report unreadable: {e}")
    return LiveResult("promptfoo", True, findings=parse_promptfoo(data))
