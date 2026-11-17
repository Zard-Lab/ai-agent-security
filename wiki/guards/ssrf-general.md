---
type: Guard
title: "ssrf-general"
description: "No SSRF from a user-controlled fetch URL."
timestamp: "2026-09-22T00:00:00+08:00"
guard_id: "ssrf-general"
checklist_section: ["3a"]
standards: ["ASVS:1.3.6", "OWASP:A10"]
---

# No SSRF from a user-controlled fetch URL

Flags a server-side HTTP fetch whose **destination host** is attacker-influenced. Closes checklist item
`3a-ssrf-general` (generalizing the LLM-only SSRF heuristic to all server-side fetches). OWASP:A10 /
CWE-918.

## The threat

Server-Side Request Forgery: `requests.get(f"https://{host}/data")` with attacker-controlled `host`
lets the attacker point your backend at internal services (`http://10.0.0.5/admin`) or the cloud
metadata endpoint (`http://169.254.169.254/latest/meta-data/iam/...`) and exfiltrate credentials —
turning the server into a proxy for things the attacker can't reach directly. Sinks: `requests.<verb>`,
`httpx.<verb>`, `urllib.request.urlopen` / bare `urlopen`.

## Exploitability rationale

HIGH. On a cloud host, SSRF to the metadata service is a direct path to IAM credential theft and lateral
movement; even without metadata, internal-service access is a serious pivot. Severity high (not critical)
because impact depends on what the network exposes.

## The trust boundary — destination host, not "is the URL dynamic?" (#861)

SSRF risk lives in the **destination**: the scheme+host the request is sent to. Interpolating a *path*
segment (`f"https://api.example.com/{name}"`) does not let the attacker choose a different server. The
guard therefore isolates the **host authority** — everything between the authority *prefix* and the
first `/`/`?`/`#` that lies outside an interpolation — and classifies where it comes from. The prefix
is a literal `scheme://`, a protocol-relative `//` (an authority *marker*, not the end of the
authority), or an **interpolated scheme** (`f"{self.scheme}://{tenant}.svc/x"`): the scheme is part of
the destination, so that interpolation is classified along with the host — a bare `{scheme}://` lets
the attacker pick the protocol (user), a config scheme on a config host stays config (#869). A single
leading `/` is a relative path, not an authority. Python's `{{`/`}}` escapes are literal braces, not
interpolations, so `f"https://{{literal}}.example.com/x"` is a fixed literal host (silent) while the
legal triple-brace `f"https://{{{tenant}}}.svc/x"` still carries a real `{tenant}` (HIGH). One
escape-aware tokenizer decides both what an interpolation is and where the authority starts; before
#869 an interpolated scheme stopped the authority walk at the `/` of its own `://` (a real SSRF
silently downgraded to non-gating MEDIUM), a `//` prefix ended it at index 0 (no finding), and an
escaped `{{x}}` read as an interpolation (spurious HIGH). It considers
**every** interpolation in that span, not just the first, so a config prefix cannot launder an
attacker-driven later segment (`f"https://{self.env}-{tenant}.svc/x"` is HIGH on `{tenant}`, #868). The
authority is host+port+userinfo, so a user-controlled *port* on a config host
(`f"https://{self.host}:{port}/x"`) also classifies **user** (an attacker can redirect to another
internal service/port); only a config port (`{self.host}:{self.port}`) stays config. The three
outcomes and their trust boundary:

| Host source | Example | Result |
|---|---|---|
| **request / bare-param / dynamic** | `f"https://{host}/x"`, `f"https://{request.args['h']}/x"`, a bare parameter | **HIGH** `ssrf-general/user-controlled-url` (gating) |
| **operator config** | `self.<attr>`, `settings.`/`config.`/`conf.`/`cfg.`/`app.` attr, an ALL-CAPS module constant incl. a leading-underscore private one (`f"{self.api_url}/x"`, `BASE = "https://…"; f"{BASE}/x"`, `_API_URL`) | **MEDIUM**, surfacing, `ssrf-general/config-host-fetch` (non-gating) |
| **literal host, path-only interp** | `f"https://api.example.com/{name}"`, a static f-string, an escaped-brace literal `f"https://{{literal}}.example.com/x"` | **silent** (not SSRF) |
| **interpolated scheme / protocol-relative prefix** (#869) | `f"{self.scheme}://{tenant}.svc/x"`, `f"//{tenant}.svc/x"` | classified like any other authority: **HIGH** on `{tenant}`; `f"{self.scheme}://{self.host}/x"` and `f"//{self.host}/x"` are **MEDIUM**; `f"//cdn.example.com/{p}"` is **silent** |

**Why downgrade config, not suppress it (the `needs-decision` ruling for #861):** the config-host case is
**downgraded and surfaced, not suppressed.** It is not directly attacker-chosen, so it must not gate CI —
7 config-host false positives in one client wrapper (`self.api_url` from `os.environ`) train users to add
blanket pragmas that then mask a real SSRF. But it is **not** treated as fully trusted the way
`path_traversal.py` treats a config path root, because in some deployments an env/config value is itself
attacker-influenceable (**SSRF-via-config**). The `medium` + surfacing rule keeps the review signal while
removing the CI-gating false positive. The literal-host path-only case, by contrast, is not SSRF under
*any* threat model, so it is suppressed outright (no policy call needed).

An ALL-CAPS name that *looks* like a module constant but is bound from a request source in the same file
(`HOST = request.args["u"]; requests.get(f"{HOST}/y")`) is **not** laundered into the config downgrade —
it stays HIGH. The shared, ReDoS-safe request-taint scan (`path_traversal.py::_tainted_names`) is reused
for this so the anti-bypass has one tested implementation.

## Following the host source through indirection (#878)

The config classification follows the host through two common indirections, each a strict **downgrade**
that only runs on a line that *already* classifies HIGH, so it can only remove a false positive and never
create one:

- **A hoisted local.** `url = f"{self.api_url}/x"; requests.get(url.format(path=p))` — the local is
  resolved to its **same-block assignment(s)** and downgraded to MEDIUM **only when *every* same-block
  assignment is a config host**. Resolution can *only* downgrade HIGH → MEDIUM; it never silences.
  A local reassigned across mutually-exclusive branches (`url = f"{host}/x"; if not host: url =
  f"{self.api_url}/x"`) is config only if **all** branches are — a single attacker-controlled branch
  keeps HIGH, so classifying only the textually-last assignment cannot launder a user branch (#881
  fresh-eyes review). The same-block rule ends a scope at a non-blank column-0 line **or** a `def`/`class`
  dedented below the assignment's own indent, so a same-named `url` in a sibling method (or another
  function) is **not** borrowed. Taint-first over the **whole fetch argument**: a `request.`/`req.`
  reference or a tainted token anywhere in it — *including inside the peeled method's own arguments*
  (`url.format(host=request.args["h"])` injects user input through `.format`) — keeps HIGH, as does an
  unresolvable local or a resolved host that is not clearly config. In particular a **plain-string**
  `.format` template whose host is a placeholder (`"http://{host}/x".format(host=…)`) keeps HIGH: this
  guard's host parser only inspects `{…}` spans inside f-strings, so it must not silence a plain string
  it cannot classify.
- **A string method over the host.** A trailing `.rstrip`/`.lstrip`/`.strip`/`.removesuffix`/
  `.removeprefix`/`.format`/`.replace` applied to the host expression is peeled off before
  classification, so `f"{self.api_url.rstrip('/')}/v"` and `f"{_API_URL.rstrip('/')}/version"` read as
  config. The peel is a manual right-to-left paren match (no backtracking regex) with the method's
  argument literals masked, so a `/`/`:`/`)` inside an argument (`.replace('http://', 'https://')`) does
  not confuse it. A request-bound method **argument** (`cfg.host.replace(evil, "")`) is caught by the
  taint check that runs *before* the peel, so peeling never launders user input.

Because both paths only ever downgrade an already-HIGH line, a bare-variable *whole* URL with no method
or concat signal (`url = f"{host}/x"; requests.get(url)`) stays silent — resolution is not a new source
of findings, only a refinement of existing ones.

## What counts as a hit (conservative by design)

SSRF detection is FP-prone, so this guard fires **only** on a clear signal in the URL argument: an
f-string, a `+`/`.format`/`%` concat, or a `request.`/`req.` reference. A **bare variable**
(`requests.get(url)`) does **not** fire on its own — too noisy — and a static literal never fires. This
deliberately trades some recall for precision; the benchmark watches the FP rate.

## When NOT to flag (and the pragma)

- `requests.get("https://api.example.com/v1")` (static literal) → silent.
- `requests.get(f"https://api.example.com/{name}")` (literal host, path-only interpolation) → silent.
- `requests.get(f"https://{{literal}}.example.com/x")` (escaped braces — a literal host) → silent.
- `requests.get(f"/{tenant}/x")` (a single leading `/` — a relative path, not an authority) → silent.
- `requests.get(URL)` where `URL` is a bare variable with no user/dynamic signal → silent (by design).
- Commented-out lines → silent.
- An audited internal fetch → suppress with `# security: allow-ssrf`.

## Known bypasses (honest limits)

- **Bare-variable / bare-parameter host.** `f"https://{host}/x"` with `host` an unannotated function
  parameter fires HIGH, and *cannot* be distinguished intra-file from a genuinely config-sourced call
  site (`get_triple_count(endpoint)` fetching `f"{endpoint}/count"` — RCA FP #9). This is the conservative
  cost: it keeps the liveness canary alive and would need cross-file call-site analysis to narrow. `url =
  request.args["u"]; requests.get(url)` (a bare-variable *whole* URL) still does not fire — the sink line
  carries no signal.
- **`+`/`%` concat hosts are not host-classified.** A `+` or `%` URL keeps firing HIGH regardless of host
  source — the host component can't be isolated from a concat reliably, so `self.base + "/x"` over-reports
  (the safe direction). (A `.format` / string-method concat over a *classifiable* config host or a
  same-block local IS now downgraded — see "Following the host source through indirection".)
- **Cross-function / cross-file indirection.** A local resolved to a hoisted assignment is only followed
  within the **same block** (`_same_block`, which treats both a column-0 line and a `def`/`class`
  dedented below the assignment — i.e. a sibling method — as a scope boundary); a URL assembled in
  another function or method, or passed in as a parameter, is not traced (it would need interprocedural
  analysis) and keeps the conservative HIGH.
- **Multi-line calls / session clients.** A `session = requests.Session(); session.get(url)` or an
  `httpx.AsyncClient()` instance method is not matched (keys on the `requests.`/`httpx.` module surface).
- **A string literal containing `(`/`)`/`,` in the fetch argument.** The single-call-argument splitter
  (`_first_arg`) tracks bracket depth without masking string literals, so a bare `)` inside an argument
  literal (`f"{self.api_url.replace(')', '/')}/v"`) truncates the argument and the finding is dropped.
  This is a pre-existing splitter limit (independent of #878, which masks literals only in the method peel)
  in the safe (under-report) direction; a normal normalizer like `.rstrip('/')` or
  `.replace('http://', 'https://')` is unaffected.

## What this guard does NOT prove

It catches a user/dynamic fetch host in source; it does not prove the host is unvalidated, nor that an
allow-listed fetch is safe. A `config-host-fetch` finding is a **surfacing** review signal, not a proven
bug — confirm the config source is not attacker-writable. Absence of a finding ≠ provably-free of SSRF —
host allow-listing plus RFC-1918/link-local/metadata blocking (resolve then check) is still the control.

## Related / follow-up

The same syntactic-taint shape lives in sibling fetch guards (`js-ssrf`, `agent-tool-url-fetch-ssrf`,
`java-ssrf`, `open-redirect`). Applying this host-source classification to them is a deliberately separate
sweep — the trusted-root vocabulary can be factored into `guards/base.py` when it does. The escaped-brace
blind spot closed here (#869) also lives in the non-escape-aware `\{([^{}]+)\}` f-string extractors of
`no-pan-stored`, `secret-str-serialized`, `sensitive-logging`, `redos`, `jwt-key-source-allowlist` and
`agent-tool-url-fetch-ssrf`; that sweep is a separate follow-up, and the tokenizer is the candidate
shared helper for it.

# Examples

Fires MEDIUM (surfacing) — operator-config host:

```python
class Client:
    def __init__(self):
        self.api_url = os.environ["FORGEJO_URL"]

    def repo(self, owner, name):
        return requests.get(f"{self.api_url}/repos/{owner}/{name}")  # config-host-fetch
```

Fires HIGH — bare-parameter / request host:

```python
def fetch(host: str):
    return requests.get(f"https://{host}/data")  # user-controlled-url
```

Silent — literal host, only a path segment interpolated:

```python
def repo(name):
    return requests.get(f"https://api.example.com/repos/{name}")
```

# Citations

[1] agentsec checklist item `3a-ssrf-general` (§3a)
[2] ASVS:1.3.6
[3] OWASP:A10
