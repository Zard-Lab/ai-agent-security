---
type: Guard
title: "npm-lifecycle-script-source-sinks"
description: "A JavaScript file run by an npm install-lifecycle script steals credentials, evals a string, or self-publishes."
timestamp: "2026-11-21T00:00:00Z"
guard_id: "npm-lifecycle-script-source-sinks"
checklist_section: ["8"]
standards: ["CWE-506", "CWE-829", "OWASP-ASI:ASI04"]
---

# An npm install-lifecycle script runs a JavaScript file that steals credentials, evals, or self-publishes

_Author — 2026-11-21_

---

## The threat

npm runs `preinstall`/`install`/`postinstall`/`prepare` automatically on install. Install-time
malware (the npm worm waves) keeps `package.json` innocent, `"postinstall": "node scripts/setup.js"`,
and puts the dropper one hop away in that file. `npm-install-script-network` only reads the script
string; this guard follows `node <file>` (and inline `node -e`) and inspects the code that will
really run. Mined from wormguard's lifecycle-script source analysis.

## Why it's often introduced

A dropper is hidden in a file because reviewers read the `package.json` diff and rarely the helper
script. Legitimate packages also use `node scripts/x.js` for native-build and binary-download steps,
which is why the rules need a credential read or an execution sink, not just a network module.

## Detection design

1. `applies()` returns `True`. Scans every `package.json`; for each lifecycle script resolves the
   `node [--flags] <file>` target (extensionless names try `.js` and `index.js`), requires it to sit
   inside the repository, and reads it with comments stripped.
2. **lifecycle-script-exfil** (HIGH): a network module (`http`/`https`/`net`/`tls`/`dns`/`dgram`,
   `fetch(`) together with a credential-file path (`.npmrc`, `.aws`, `.ssh`, `.netrc`, `id_rsa`,
   `.git/config`, `.docker/config`, `.kube/config`), a whole-environment dump, or a secret-named
   env var (`*TOKEN*`, `*SECRET*`, `AWS_*`, ...).
3. **lifecycle-script-base64-exec** (HIGH): `Buffer.from(<24+ char literal>, 'base64')` plus an
   execution sink (`eval`, `new Function`, `vm.run*`, `child_process`, `exec`/`spawn`).
4. **lifecycle-script-dynamic-eval** (MEDIUM): `eval(` or `new Function(`.
5. **lifecycle-script-worm-propagate** (HIGH): writes `package.json` and runs `npm publish`.
6. Suppress with `// security: allow-npm-lifecycle-script-source-sinks` in the JS file, or the
   literal anywhere in `package.json`.

## When NOT to flag

- A download script that reads `process.env.CI`, `npm_config_*` or proxy variables.
- Network code with no credential read; a credential-path read with no network module.
- Sinks in comments; a file only run by a non-lifecycle script; a path escaping the repository.
- `node-gyp rebuild`, `husky install`, `prebuild-install`.

## Tests

| Test | What it checks |
|---|---|
| `test_exfil_*` / `test_inline_node_eval_program_is_analysed` | Exfil fires, including `node:https` ESM, env spread and inline `node -e` |
| `test_base64_decode_then_exec_fires` | Decode-then-exec |
| `test_worm_pair_fires` / `test_worm_pair_with_spawn_array_form_fires` | Worm pair, exec and spawn forms |
| `test_dynamic_eval_alone_is_medium` | eval alone is MEDIUM |
| `test_binary_download_script_with_ordinary_env_is_safe` and the other `*_is_safe` tests | FP-bait |
| `test_pragma_in_js_file_suppresses` / `test_pragma_in_package_json_suppresses` | Pragma |

## Known bypasses

- Only `node <file>` and `node -e` are followed; `npm run x`, shell wrappers, a computed `require`
  and payloads split across files are not traced.
- Obfuscated module names (`require('ht' + 'tps')`) hide the network module.
- Files over 1 MB are skipped.

## What this guard does NOT prove

Silence does not prove the script is safe, only that none of these four shapes appear in the one
file the lifecycle script names.

# Citations

[1] agentsec checklist item `8-npm-lifecycle-script-source-sinks` (§8)
[2] wormguard, lifecycle-script resolution and sink analysis
[3] CWE-506, CWE-829, OWASP-ASI:ASI04
