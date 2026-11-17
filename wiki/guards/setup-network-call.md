---
type: Guard
title: "setup-network-call"
description: "setup.py performs a network call at module top level or in a cmdclass command's run(), running on every pip install/build from source."
timestamp: "2026-10-19T00:00:00Z"
guard_id: "setup-network-call"
checklist_section: ["8"]
standards: ["OWASP:A08", "CWE-829", "CWE-494"]
---

# setup.py performs a network call at module top level

_Author — 2026-10-18_

---

## The threat

`setup.py` runs on every `pip install`/`python setup.py build` from source, with no
confirmation, before the package's own code has been reviewed or even installed. A network
call at module TOP LEVEL (not wrapped in a function) runs unconditionally the instant the file
is executed — the same install-time-execution class the 2026-03-31 Claude Code supply-chain
compromise and the OpenClaw CVE chain both used via npm's lifecycle scripts, applied here to
Python's equivalent surface.

WHO reaches this: anyone who runs `pip install` on the package, or any build tooling that
executes `setup.py` from source. WHAT privilege / TO WHAT EFFECT: a network fetch the installer
never agreed to, at the point in the chain where the fetched content has had zero review — the
same leverage a malicious `postinstall` script has. Standards: OWASP:A08 (Software and Data
Integrity Failures), CWE-829 (Inclusion of Functionality from Untrusted Control Sphere),
CWE-494 (Download of Code Without Integrity Check).

## Why it's often introduced / why no existing agentsec guard covers this

`npm-install-script-network` covers the exact same threat class for npm's lifecycle scripts —
confirmed by grepping it, `python_supply_chain.py`, and every other guard for `setup.py`/
`install-time`/`install_time` before building anything: zero hits. The Python side of this
install-time-execution class had no guard at all.

## Detection design

Ported from `rakshit-737/warden-supply-chain-security`'s `warden-python.yml` semgrep rule
(`warden.install_time_execution.setup-network-call`, fetched and read in full).

**`setup-py-network-call` (HIGH).**

1. **`applies()` gate:** `"python" in profile.features`.
2. **Files scanned:** any file literally named `setup.py`, anywhere in the repo (matching the
   source's own `"setup.py"`/`"**/setup.py"` path scope).
3. **AST-based, not regex:** parses the file and walks only statements NOT nested inside a
   `FunctionDef`/`AsyncFunctionDef`/`ClassDef`/`Lambda` — those only run when actually invoked,
   not at import time. Flags a module-level `Call` whose dotted name is one of: `urllib.
   request.urlopen`/`urlretrieve`, `urllib.urlopen`/`urlretrieve`, `urllib2.urlopen`,
   `requests.get`/`post`/`put`/`delete`/`head`/`options`/`request`, `httpx`'s same verb set,
   `http.client.HTTPConnection`/`HTTPSConnection`, or `socket.create_connection`/
   `getaddrinfo`/`gethostbyname`.

**`setup-cmdclass-network-call` (HIGH).** The classic malicious `setup.py` shape, which the
module-level rule cannot see because it skips class bodies: a custom command class passed
through `setup(cmdclass={"install": CustomInstall})` (or `setuptools.setup(...)`) whose own
`run()` method makes one of the network calls above. setuptools calls that `run()` itself during
`pip install`, so the call is as install-time-unconditional as a module-level one. Each `Name`
value of a literal `cmdclass={...}` dict is resolved to its `ClassDef` in the same file, and that
class's `run` body is walked (nested definitions included) for the first matching call. A class
with a `run()` that is NOT in `cmdclass`, and a `cmdclass` command whose `run()` makes no network
call, stay silent. Added in the PR #1093 review fix pass; the guard missed this shape entirely
before.

**Deliberately simpler than the source:** the source's own rule also matches a raw
`socket.socket(...).connect(...)` chain and a bare `$SOCK.connect(...)` where `$SOCK` was
assigned from `socket.socket(...)` earlier — tracking that assignment chain needs real AST
dataflow. Dropped here as the noisiest, lowest-marginal-value sub-pattern; the fixed-function
calls above already cover the overwhelming majority of real `setup.py` network fetches.

**Inline opt-out pragma:** `# security: allow-setup-network-call`.

## When NOT to flag

- **A network call wrapped inside a function definition, or in a class that is not a
  `cmdclass` command** — it only runs if and when something calls it, not automatically on
  install. (A `cmdclass` command's `run()` is the exception, because setuptools calls it: see
  `setup-cmdclass-network-call` above.)
- **An ordinary `setup.py`** with no network call at all (the overwhelming majority).
- **Any file not literally named `setup.py`** — out of this guard's scope entirely.

Use the pragma `# security: allow-setup-network-call` for a vendored build step with a
genuinely reviewed, pinned fetch.

## Tests

| Test | What it checks |
|---|---|
| `test_fires_on_module_level_urlopen` | `urllib.request.urlopen(...)` at module top level — fires HIGH |
| `test_fires_on_requests_get_at_module_level` | `requests.get(...)` at module top level — fires |
| `test_fires_on_nested_setup_py_path` | a `setup.py` under a subdirectory — fires |
| `test_fires_on_network_call_in_cmdclass_install_run` | `cmdclass={"install": C}` whose `C.run()` calls `requests.get` — fires `setup-cmdclass-network-call` |
| `test_class_with_run_method_not_in_cmdclass_does_not_fire` | FP-bait: a class with a networking `run()` that `cmdclass` never names — silent |
| `test_cmdclass_without_network_call_does_not_fire` | FP-bait: a `cmdclass` command whose `run()` makes no network call — silent |
| `test_network_call_inside_a_function_does_not_fire` | FP-bait: the same call wrapped in a `def` — silent |
| `test_ordinary_setup_py_does_not_fire` | FP-bait: a plain `setuptools.setup(...)` call — silent |
| `test_non_setup_py_file_is_not_scanned` | FP-bait: the identical pattern in a differently-named file — silent |
| `test_pragma_silences` | the inline pragma silences the rule |
| `test_applies_requires_python` | `applies()` gate |

## Known bypasses

- **Dropped raw-socket pattern (disclosed above).**
- **Indirect invocation.** A module-level call to a locally-defined wrapper function that
  itself makes the network call is not traced, and neither is a `cmdclass` `run()` that calls
  such a helper — only a DIRECT call to one of the fixed dotted names is recognized.
- **Textual names, no import resolution.** The dotted name is read as written, so an aliased
  import (`import requests as r; r.get(...)`) or a `from` import (`from urllib.request import
  urlopen; urlopen(...)`) is not recognized, at module level or in `run()`.
- **Only a literal `cmdclass` dict.** `cmdclass=cmds` (a dict held in a variable),
  `cmdclass=dict(install=C)`, and a `run()` inherited from a local base class are not resolved.
- **Fixed call vocabulary.** A network library not in the fixed list (`aiohttp`, a raw `ftplib`
  call, etc.) is not recognized.

## What this guard does NOT prove

- That a flagged call is actually malicious — a legitimate build step that fetches a prebuilt
  binary (with its own out-of-band checksum verification this pattern cannot see) still
  matches; this guard surfaces the capability for human review, the same posture as
  `npm-install-script-network`.
- That a `setup.py` WITHOUT a matching pattern never reaches the network — a call routed
  through a module-level conditional calling an unrecognized library, or deferred via
  `importlib`, is not caught.

# Citations

[1] agentsec checklist item `8-setup-network-call` (§8)
[2] OWASP:A08, CWE-829, CWE-494
[3] rakshit-737/warden-supply-chain-security `warden-python.yml` (`setup-network-call`)
[4] sibling guard: `npm-install-script-network` (the npm-side equivalent of this threat class)
