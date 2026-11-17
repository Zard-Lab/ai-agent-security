---
type: Guard
title: "staticfiles-broad-mount"
description: "StaticFiles mounted at project root or filesystem root — exposes source code and secrets."
timestamp: "2026-06-21T18:50:26+08:00"
guard_id: "staticfiles-broad-mount"
checklist_section: ["6a"]
standards: ["OWASP:A01", "OWASP:A05"]
---

# StaticFiles mounted at project root or filesystem root — exposes source code and secrets

## Threat

FastAPI's `StaticFiles` middleware serves every file under its `directory` argument as a
public HTTP asset. When that argument is `"."` (the process working directory, typically the
project root), `"/"` (the filesystem root), or `".."` (the parent directory), the web server
exposes the entire file tree without authentication.

An attacker who discovers the mount URL can retrieve:

- `.env` — API keys, database passwords, JWT secrets
- Source code — proprietary logic, hardcoded tokens, internal endpoints
- `pyproject.toml` / `requirements.txt` — exact dependency versions for targeted CVE attacks
- Private key files, SSL certificates, migration scripts

The exploit is a single unauthenticated GET request. No special tooling or privileges are
required: a browser, `curl`, or a directory-traversal wordlist suffices.

**References:** OWASP Top 10 A05:2021 (Security Misconfiguration), CWE-552 (Files or
Directories Accessible to External Parties).

## Detection design

The guard scans Python files for two literal-match patterns:

**Pattern 1 — direct constructor call**

```
StaticFiles\s*\(\s*(?:directory|html)\s*=\s*['"](?:\.|/|\.\.)['"]
```

Catches:
- `StaticFiles(directory=".")` — current directory
- `StaticFiles(directory="/")` — filesystem root
- `StaticFiles(directory="..")` — parent directory
- `StaticFiles(html=".")` — same danger via the `html=` keyword

**Pattern 2 — mount call**

```
mount\s*\(\s*['"][^'"]*['"]\s*,\s*StaticFiles\s*\(\s*directory\s*=\s*['"](?:\.|/)['"]
```

Catches the `app.mount("/static", StaticFiles(directory="/"))` compound form explicitly,
ensuring the mount context is recognized even if pattern 1 is modified.

Both patterns apply only to `.py` files discovered via `python_scan_dirs` + `iter_files`.
File-level pragma suppression (`# security: allow-staticfiles-mount`) skips the entire file.

## Severity rationale

**HIGH.** The impact is immediate and total: one unauthenticated HTTP request retrieves
production secrets. No chaining, no privilege escalation, no exploitation of a secondary
vulnerability is required. The attack surface is the HTTP port itself — public by design.

CRITICAL would require remote code execution as the immediate outcome; HIGH is correct here
because the direct consequence is credential disclosure and source exposure, not direct RCE
(though secondary RCE via the leaked credentials is trivial).

## Known bypasses

| Bypass | Guard catches it? | Notes |
|---|---|---|
| `directory="."` literal | Yes | Both patterns match |
| `directory="/"` literal | Yes | Both patterns match |
| `directory=".."` literal | Yes | Pattern 1 matches |
| Directory read from env var: `directory=os.getenv("STATIC_DIR", ".")` | No | Requires dataflow analysis; falls outside static line-level detection |
| Directory computed at runtime: `directory=str(Path.cwd())` | No | Dynamic path; not a literal |
| Variable alias: `d = "."; StaticFiles(directory=d)` | No | Multi-statement; not a literal |
| Pragma opt-out: `# security: allow-staticfiles-mount` | Suppressed intentionally | Reviewer must confirm runtime safety |

## FP scenarios

| Scenario | Fires? | Rationale |
|---|---|---|
| `StaticFiles(directory="static")` | No | Safe relative subdir; pattern requires `"."`, `"/"`, or `".."` |
| `StaticFiles(directory="frontend/build")` | No | Safe explicit path; no match |
| `StaticFiles(directory="assets/images")` | No | Safe path; no match |
| `StaticFiles(directory="./static")` | No | `"./static"` is not `"."` — the regex anchors on quote boundaries |
| `StaticFiles(directory="../other-safe-dir")` | No | Not a bare `".."` — the regex requires the closing quote immediately after `..` |
| Test file using `"."` with pragma | Suppressed | Pragma opt-out applied correctly |

## Checklist items flipped

| Checklist item | Section | Status this guard provides |
|---|---|---|
| `6a-staticfiles-safe-mount` | §6a Frontend Security | `covered` — catches direct literal root/parent mounts |

## Tests

| Test function | Fixture | Expected outcome |
|---|---|---|
| `test_staticfiles_fires_on_dot_directory` | `app.mount("/", StaticFiles(directory="."))` | 1 finding, rule = `staticfiles-broad-mount/root-or-parent-dir-mounted`, severity = high |
| `test_staticfiles_fires_on_slash_directory` | `app.mount("/static", StaticFiles(directory="/"))` | 1 finding fired |
| `test_staticfiles_fires_on_dotdot_directory` | `StaticFiles(directory="..")` | 1 finding fired |
| `test_staticfiles_silent_on_safe_path` | `StaticFiles(directory="static")` and `StaticFiles(directory="frontend/build")` | 0 findings |
| `test_staticfiles_pragma_suppresses` | File with `StaticFiles(directory=".")` and pragma comment | 0 findings |
| `test_staticfiles_applies_gate` | `features=set()` (no fastapi, no python) | `applies()` returns False |

# Citations

[1] agentsec checklist item `6a-staticfiles-safe-mount` (§6a)
[2] OWASP:A01
[3] OWASP:A05
