---
type: Guard
title: "npm-install-script-network"
description: "An npm install-lifecycle script reaches the network, or a dependency name typosquats a trusted MCP package."
timestamp: "2026-09-26T00:00:00Z"
guard_id: "npm-install-script-network"
checklist_section: ["8"]
standards: ["CWE-829", "CWE-1021", "OWASP-ASI:ASI04"]
---

# npm install-lifecycle script reaches the network, or a dependency name typosquats a trusted MCP package

_Author — 2026-09-26_

---

## The threat

npm runs `preinstall`/`postinstall`/`prepare` scripts automatically, with no confirmation, the
instant a package is installed — the exact mechanism the 2026-03-31 Claude Code supply-chain
compromise (a poisoned `axios` dependency) and the disclosed 104-CVE OpenClaw chain (Adversa AI)
both used to reach arbitrary code execution on a developer's machine. A script that fetches
content over the network during install, before any of the package's own code has been reviewed
or even fully installed, is the highest-leverage point in the whole dependency chain to
compromise. Separately, a dependency whose name is a near-miss of a well-known, trusted MCP
package name is a classic typosquat: a developer or an automated dependency-add tool believes it
is installing the real package. Sourced from `agent-audit-kit`'s `supply_chain.py`
(AAK-SUPPLY-001/002), verified against the real repo source.

**Deliberately not ported: AAK-SUPPLY-003**, a set of specific hardcoded `axios`/`openclaw`
version pins — those belong in `version_floors.json` after independent verification against real
PyPI/npm/NVD data (tracked as a separate, not-yet-done task), not fabricated here as a
source-check.

## Why it's often introduced

An install-lifecycle script fetching content is often a legitimate-looking build step (fetching a
prebuilt binary, a font, a platform-specific asset) that happens to route through `curl`/`wget`
rather than npm's own registry-resolved dependency mechanism — the line between "ordinary asset
fetch" and "supply-chain compromise vector" is invisible from the script alone. A typosquat
dependency is added the same way any dependency is: copy-pasted from an untrusted source, or
mistyped once and never re-checked.

## Detection design

1. `applies()` returns `True` unconditionally.
2. Scans every `package.json` file (`iter_files_named`).
3. **install-script-network-call** (HIGH): the `scripts.preinstall`/`scripts.install`/
   `scripts.postinstall`/`scripts.prepare` value invokes a network-capable command (`curl`/`wget`/
   `fetch`/`nc`/`ncat`/`ssh`/a bare `http`/`https` URL/`axios`/`request`) at a COMMAND position —
   `fetch` needs a preceding separator, and every word needs no `-`/`:`/`.`/word-character
   directly after it, so `npm run fetch-assets`, `fetch:data` and `node scripts/curl.js` are
   script/file NAMES, not commands, and stay silent.
4b. **install-script-shell-obfuscation** (HIGH): the same four lifecycle values pipe into a shell (`| sh`/`bash`/`zsh`/`pwsh`), decode base64 (`base64 -d`, `openssl base64 -d`), or run `eval`/`source` at a command position. No network word is required: `echo <b64> | base64 -d | sh` reaches no network yet runs an opaque payload. `node-gyp rebuild`, `husky install` and `prebuild-install` stay silent.
4. **mcp-package-typosquat** (HIGH): a `dependencies`/`devDependencies`/`optionalDependencies`
   entry's package name is a near-miss (length within 2, a substring relationship, or all-but-one
   shared characters) of a well-known, trusted MCP package name (`@modelcontextprotocol/sdk` and
   its official server packages, `fastmcp`, `mcp-server`, `mcp-framework`), without matching it
   exactly. A trailing plural `s` or version digit (`mcp-servers`, `fastmcp2`) is its own, distinct
   package name and is exempted.
5. Suppress with a literal `security: allow-npm-install-script-network` string anywhere in the
   JSON document (JSON has no comment syntax).

## When NOT to flag

- No network-capable command in any of the three install-lifecycle script keys.
- A network command in an ordinary, explicitly-invoked script (e.g. `deploy`) that doesn't run
  automatically on install.
- The exact, correctly-spelled trusted package name.
- An unrelated package name that shares no near-miss relationship with any trusted name.

## Tests

| Test | What it checks |
|---|---|
| `test_postinstall_curl_pipe_bash_fires` / `test_preinstall_wget_fires` / `test_prepare_script_with_network_fires` | All three lifecycle keys fire on a network command |
| `test_benign_install_script_is_safe` | FP-bait: an ordinary build-step script with no network command |
| `test_network_command_in_non_lifecycle_script_is_safe` | FP-bait: a network command in a non-lifecycle script |
| `test_mcp_sdk_typosquat_fires` / `test_typosquat_in_dev_dependencies_fires` | Typosquat in `dependencies` and `devDependencies` |
| `test_exact_trusted_mcp_package_is_safe` | FP-bait: the exact trusted name doesn't fire on itself |
| `test_unrelated_package_name_is_safe` | FP-bait: ordinary, unrelated package names |
| `test_pragma_suppresses_all_findings` | The JSON-literal pragma silences every rule |
| `test_shell_obfuscation_in_lifecycle_fires` / `test_ordinary_lifecycle_scripts_have_no_obfuscation_finding` | Pipe-to-shell, base64 decode and eval/source fire; native-build and hook-install scripts stay silent |
| `test_applies_universally` | `applies()` is unconditionally `True` |

## Known bypasses

- The network-command vocabulary is a fixed word list; a downloader this guard doesn't name (a
  language-specific one-liner, a compiled helper binary already present) is invisible.
- The typosquat heuristic (length + substring + character-overlap) can both miss a
  cleverly-different-looking impersonation and, rarely, flag a genuinely unrelated short name that
  happens to share most characters with a trusted one.
- The trusted-package-name list is fixed and necessarily incomplete — a popular MCP package not
  on this list offers no typosquat protection.
- A script that reaches the network indirectly (calling a local helper script that itself curls)
  rather than inline in the `package.json` value is not traced.

## What this guard does NOT prove

Silence does not prove a package's install lifecycle is safe — only that these two specific,
dataset-anchored shapes are absent. A malicious payload delivered without a network fetch (bundled
directly in the package, or fetched via a mechanism this guard's vocabulary doesn't name) is
outside this guard's static-text scope.

# Citations

[1] agentsec checklist item `8-npm-install-script-network` (§8)
[2] 2026-03-31 Claude Code supply-chain compromise (poisoned `axios` dependency)
[3] OpenClaw 104-CVE chain (Adversa AI disclosure)
[4] CWE-829 (Inclusion of Untrusted Functionality), CWE-1021, OWASP-ASI:ASI04 — standards
    consistent with `skill-poisoning`'s own `trusted-name-typosquat` rule, the same heuristic
    applied to a different namespace
[5] agent-audit-kit `supply_chain.py`, rules AAK-SUPPLY-001/002
