---
type: Guard
title: "slopsquatting"
description: "Package name confusion or TLS bypass in dependency installation."
timestamp: "2026-06-28T17:07:07+08:00"
guard_id: "slopsquatting"
checklist_section: ["4"]
standards: ["OWASP-LLM:LLM03", "OWASP:A06"]
---

# Package name confusion or TLS bypass in dependency installation

_Author — 2026-06-28_

---

## The threat

**Slopsquatting** is the attack surface created when an LLM hallucinates a package
name that does not exist on PyPI or npm, and an attacker pre-registers that name as
a malicious package. The four enabling conditions this guard detects:

1. **MLSC-016 — TLS bypass via `--trusted-host`** (HIGH): A `pip install
   --trusted-host <host>` line disables TLS certificate validation for that
   host. An attacker who can intercept traffic between the build machine and
   the package server can serve a modified package — the client accepts it
   because certificate verification is off.

2. **MLSC-022 — HTTP pip index** (HIGH): `--index-url http://...` or
   `--extra-index-url http://...` sends package download requests over
   unencrypted HTTP. Any network path attacker can substitute the package.

3. **MLSC-021 — Cross-ecosystem pip install** (CRITICAL): LLMs commonly
   suggest `pip install react`, `pip install webpack`, `pip install lodash`,
   etc. These are npm packages; they do not belong on PyPI. If an attacker
   has registered them on PyPI, `pip install` will silently install the
   attacker's package. This is the purest slopsquatting signal.

4. **SQ-085 — HTTP npm registry** (HIGH): An `.npmrc` or `package.json`
   pointing at an `http://` registry gives the same MitM surface for the npm
   ecosystem.

Standards (per rule): the transport rules (1 `--trusted-host`, 2 HTTP pip index, 4 HTTP npm
registry) are TLS/cryptographic failures → `OWASP:A02` + `OWASP:A06` + `OWASP-LLM:LLM03`. The
cross-ecosystem rule (3) is purely supply-chain → `OWASP:A06` + `OWASP-LLM:LLM03`.

## Why it's often introduced / Why this guard fits the stack

Developers using AI coding tools or copying AI-generated snippets frequently
accept install commands verbatim. A confused LLM that merges JS and Python
knowledge might output:

```bash
pip install react requests   # react does not exist on PyPI (legitimately)
```

Or a corporate developer who configures an internal registry might use HTTP
out of laziness or corporate proxy workarounds:

```bash
pip install --trusted-host nexus.corp --extra-index-url http://nexus.corp/pypi/ mylib
```

Both patterns are invisible to normal testing: the install succeeds (either
because the package truly exists on PyPI under that name, or because the
internal server answers), and the resulting binary may appear to work while
silently executing a backdoor payload.

## Detection design

1. **`applies(profile)`**: fires when `"python"` or `"frontend"` is in
   `profile.features` (pip affects Python stacks; npm registry affects
   frontend stacks; either stack can carry cross-ecosystem confusion).

2. **Files scanned**:
   - Rules 1–3: `.py`, `.sh`, `.cfg`, `.ini`, `.txt`, `.yml`, `.yaml`,
     `.toml`, plus `Dockerfile*` and `Makefile` (via `iter_files_named`).
   - Rule 4 (npm): `.npmrc` files (via `iter_files_named`) and `package.json`
     files (via `iter_files_named`).

3. **Patterns**:
   - Rule 1: `r"pip\s+install\b[^\n]*--trusted-host"` — multiline, skips
     lines where the whole line is a comment (`#` or `//` prefix).
   - Rule 2: `r"--(?:extra-)?index-url\s+http://"` — matches both
     `--index-url` and `--extra-index-url` pointing at HTTP. Skips comment lines
     and lines whose http host is loopback (`localhost`/`127.0.0.1`/`::1`), which
     carry no MitM risk (mirrors `pg_ssl_required`'s loopback carve-out).
   - Rule 3: **tokenised**, not substring-matched. Each non-comment `pip install`
     line is parsed by `_pip_install_targets()`: flags (and their separate args,
     e.g. `-r <file>`, `--index-url <url>`) are skipped, an inline `#` comment tail
     is dropped, and version specifiers / extras are stripped. A finding fires only
     when a resulting **bare install target** exactly equals a `KNOWN_NPM_ONLY`
     name. So `pip install django-react-templatetags` and `pip install -r
     react-reqs.txt` do NOT fire, while `pip install react==18.2.0` does.
     `KNOWN_NPM_ONLY` is curated against PyPI to **exclude names that are also real
     Python packages** (babel, sass, moment, lodash, prettier, parcel, vite, nuxt,
     next, tailwindcss, autoprefixer were removed): 16 names remain (react,
     react-dom, vue, angular, webpack, webpack-cli, typescript, express, axios,
     jquery, babel-core, eslint, postcss, rollup, svelte, node-sass).
   - Rule 4: `r"registry\s*=\s*http://"` in `.npmrc`;
     `r'"registry"\s*:\s*"http://'` in `package.json`. Comment lines (npmrc) and
     loopback hosts are skipped.

4. **Pragma**: `# security: allow-slopsquatting` anywhere in the file
   suppresses all rules for that file.

5. **Severities, rule ids, and standards**:
   | Rule | Severity | rule id | standards |
   |---|---|---|---|
   | MLSC-016 | `high` | `slopsquatting/pip-trusted-host-tls-bypass` | A02, A06, LLM03 |
   | MLSC-022 | `high` | `slopsquatting/pip-http-index` | A02, A06, LLM03 |
   | MLSC-021 | `critical` | `slopsquatting/cross-ecosystem-pip-install` | A06, LLM03 |
   | SQ-085   | `high` | `slopsquatting/npm-http-registry` | A02, A06, LLM03 |

## When NOT to flag

- A commented-out `pip install --trusted-host` example in documentation should
  not fire — the comment-line check skips these.
- `--extra-index-url https://...` is HTTPS and never fires rule 2.
- `pip install requests flask pydantic` — real PyPI packages, not in
  `KNOWN_NPM_ONLY`, so rule 3 stays silent.
- `pip install babel` / `sass` / `moment` — these ARE real PyPI packages; they were
  deliberately removed from `KNOWN_NPM_ONLY`, so rule 3 stays silent.
- `pip install django-react-templatetags` / `pip install -r react-reqs.txt` — the
  npm name is only a substring / a flag argument, not a bare install target, so the
  tokeniser does not flag it.
- `--index-url http://127.0.0.1:3141/...` / `registry=http://localhost:4873/` — local
  dev index/registry over loopback HTTP, no MitM path, stays silent.
- `registry=https://registry.npmjs.org/` in `.npmrc` — HTTPS, stays silent.
- Any file containing the pragma `# security: allow-slopsquatting` is fully
  suppressed — use this when an HTTP registry is intentional (e.g., a
  corporate private registry that is only accessible inside a VPN and whose
  HTTP exposure is accepted risk).

## Tests

| Test | What it checks |
|---|---|
| `test_slopsquatting_applies_to_python` | applies() returns True for python feature |
| `test_slopsquatting_applies_to_frontend` | applies() returns True for frontend feature |
| `test_slopsquatting_does_not_apply_to_empty_stack` | applies() returns False for empty stack |
| `test_pip_trusted_host_fires_on_install_line` | Rule 1 violation in .sh file |
| `test_pip_trusted_host_fires_in_dockerfile` | Rule 1 violation in Dockerfile |
| `test_pip_trusted_host_silent_on_comment_line` | Rule 1 FP-bait: commented-out line |
| `test_pip_trusted_host_silent_with_pragma` | Rule 1 suppressed by pragma |
| `test_pip_http_index_fires_on_extra_index_url` | Rule 2 violation: --extra-index-url http:// |
| `test_pip_http_index_fires_on_index_url` | Rule 2 violation: --index-url http:// |
| `test_pip_https_index_is_silent` | Rule 2 FP-bait: HTTPS index is safe |
| `test_pip_http_index_silent_with_pragma` | Rule 2 suppressed by pragma |
| `test_cross_ecosystem_pip_fires_on_react` | Rule 3 violation: pip install react |
| `test_cross_ecosystem_pip_fires_on_webpack_in_dockerfile` | Rule 3 violation in Dockerfile |
| `test_cross_ecosystem_pip_silent_for_real_pypi_packages` | Rule 3 FP-bait: real packages |
| `test_cross_ecosystem_pip_silent_with_pragma` | Rule 3 suppressed by pragma |
| `test_cross_ecosystem_pip_silent_on_comment_line` | Rule 3 FP-bait: commented-out line |
| `test_npm_http_registry_fires_in_npmrc` | Rule 4 violation: .npmrc http:// |
| `test_npm_https_registry_silent_in_npmrc` | Rule 4 FP-bait: HTTPS registry |
| `test_npm_http_registry_fires_in_package_json` | Rule 4 violation in package.json |
| `test_npm_http_registry_silent_with_pragma` | Rule 4 suppressed by pragma |
| `test_cross_eco_silent_on_legit_pypi_babel` | Rule 3 FP-bait: `pip install babel` (real PyPI) stays silent |
| `test_cross_eco_silent_on_hyphenated_name` | Rule 3 FP-bait: `django-react-templatetags` substring stays silent |
| `test_cross_eco_silent_on_requirements_file_name` | Rule 3 FP-bait: `-r react-reqs.txt` flag arg stays silent |
| `test_cross_eco_fires_on_versioned_target` | Rule 3: `react==18.2.0` still fires (tokeniser strips spec) |
| `test_http_index_silent_in_comment` | Rule 2 FP-bait: commented http index stays silent |
| `test_http_index_silent_on_loopback` | Rule 2 FP-bait: `http://127.0.0.1` devpi stays silent |
| `test_npm_http_registry_silent_on_loopback` | Rule 4 FP-bait: `http://localhost` verdaccio stays silent |

## Known bypasses

- **Shell variable indirection**: `HOST=pypi.attacker.com; pip install --trusted-host $HOST pkg`
  — the guard scans raw text and does not resolve variables, so this bypasses rule 1.
- **Multi-line pip install** with continuation (`\`): if `--trusted-host` lands on a
  continuation line, the regex (which is single-line within `[^\n]*`) may not match
  the full command. Dockerfile `RUN pip install \` + `    --trusted-host ...` would
  be detected because the `\` makes it continue on a new line that the regex does
  not see.
- **Alias or wrapper**: `pip3 install --trusted-host ...` — the guard matches
  `pip\s+install`, so `pip3` (not `pip `) is not matched. Add `pip3` to the pattern
  if this becomes a FP vector in practice.
- **KNOWN_NPM_ONLY is finite and conservative**: an LLM can hallucinate any package
  name not in the set. The set is deliberately curated to EXCLUDE npm names that are
  also real PyPI packages (babel, sass, moment, …), since a CRITICAL false positive on
  a legitimate Python install is worse than missing one npm name — so some npm names
  are intentionally not flagged.
- **Whiteout via pragma on a higher-level config**: an `.npmrc` with the pragma
  suppresses the npm registry check for that file only; a `registry=http://...` in a
  nested `.npmrc` in a subdirectory will still fire.

## What this guard does NOT prove

- It does not verify that any specific package has a malicious payload — it only
  flags conditions that make supply-chain substitution possible.
- It does not scan `requirements.txt` for typosquatting (similar-looking names like
  `reqeusts` vs `requests`) — that requires a fuzzy-match check, not a fixed-name
  match.
- It does not detect `pip install` inside Python `subprocess.run(...)` calls — those
  require dynamic analysis.
- It does not confirm that the npm registry at `https://...` is trusted — only that
  it uses HTTPS.

# Citations

[1] agentsec checklist item `4-hallucinated-dependency-pinning` (§4)
[2] OWASP-LLM:LLM03
[3] OWASP:A06
