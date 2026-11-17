---
type: Guard
title: "mcp-tunnel-config-security"
description: "An MCP Tunnels gateway config disables its own SSRF defense, forwards to HTTPS with no trust anchor, or leaks tunnel credentials."
timestamp: "2026-10-06T00:00:00Z"
guard_id: "mcp-tunnel-config-security"
checklist_section: ["4"]
standards: ["CWE-918", "CWE-295", "CWE-798"]
---

# MCP Tunnels gateway config disables SSRF defense, lacks a TLS trust anchor, or leaks credentials

_Author — 2026-09-26_

---

## The threat

Anthropic MCP Tunnels (research preview, launched 2026-05-19) route outbound-only traffic
through a gateway proxy to private MCP servers. Per the official reference and security
docs, three misconfigurations are explicitly named as high-risk: disabling
`upstream.allowed_ips`/`disable_ip_validation` (the proxy's own documented "primary SSRF
defense"), forwarding to an `https://` upstream with no trust anchor ("otherwise the proxy
has no trust anchor for the upstream certificate," quoted verbatim), and hardcoding the
tunnel token or server TLS private key — both named explicitly as high-value secrets whose
combined compromise lets an attacker "impersonate your proxy and read MCP request
payloads." CWE-918 (SSRF), CWE-295 (Improper Certificate Validation), CWE-798 (Use of
Hard-coded Credentials). Sourced from `agent-audit-kit`'s `mcp_tunnel.py`
(AAK-MCP-TUNNEL-001/002/003), verified against the real repo source and the official docs
it cites.

## Why it's often introduced

`disable_ip_validation: true` and a broad `allowed_ips` CIDR are common "just get it
working" shortcuts during initial gateway setup, left in place after the fact. The TLS
trust-anchor requirement is easy to miss because the tunnel's OUTER transport (cloudflared
→ edge → proxy) is already TLS-protected, so the proxy's OWN inner connection to the
upstream feels redundant to secure — but it is exactly the leg the reference docs call out.

## Detection design

1. `applies()` gates on `"mcp" in profile.features`.
2. A file is a tunnel proxy config when named `config.yaml`/`config.yml`/`proxy.yaml`/
   `proxy.yml`/`values.yaml`/`values.yml`, OR sits under a directory hinting at MCP Tunnels
   (`mcp-gateway`/`mcp-tunnel`/`gateway`/`tunnel`/...), AND its parsed YAML carries the
   unambiguous `tunnel_domain` + `routes` shape (directly, or nested under a Helm
   `gateway.config` wrapper).
3. **ssrf-defense-disabled** (CRITICAL): `upstream.disable_ip_validation: true`, or an
   `upstream.allowed_ips` entry whose CIDR prefix is ≤7 (IPv4) / ≤31 (IPv6), or the literal
   `0.0.0.0/0`/`::/0`.
4. **no-upstream-trust-anchor** (HIGH): a `routes` entry forwards to an `https://` upstream
   while neither `upstream.tls.ca_file` (non-empty) nor `upstream.tls.include_system_cas:
   true` is set.
5. **tunnel-credential-hardcoded** (CRITICAL), three independent sub-checks:
   a tunnel-token-shaped env var (`MCP_TUNNEL_TOKEN`/`TUNNEL_TOKEN`/
   `ANTHROPIC_TUNNEL_TOKEN`/`TUNNEL(S)_API_TOKEN`/`ANTHROPIC_IDENTITY_TOKEN`) with a
   literal (non-`${...}`/non-`secrets.`/non-`env.`) value in a CI workflow file; a PEM
   private-key header committed under a tunnel-hinted path; or a Kubernetes `Secret`
   manifest named `mcp-tunnel`/`mcp-tunnel-token`/`mcp-tunnel-cert` checked in with a
   non-empty literal `data`/`stringData` value.
6. Inline opt-out: a `# security: allow-mcp-tunnel-config-security` comment anywhere in the file
   silences the file (a quoted YAML scalar carrying the phrase does not count, #424). In a CI
   workflow, a `#` shell comment inside a `run: |` script counts too. A committed key file has no
   comment syntax, so there the phrase is matched in the raw text.
7. Standards per rule: `["CWE-918", "OWASP:A10"]` (SSRF), `["CWE-295", "OWASP:A02"]` (TLS),
   `["CWE-798", "OWASP:A02"]` (credentials).

## When NOT to flag

- A narrow, real internal-network CIDR in `allowed_ips`.
- An `https://` route with `ca_file` or `include_system_cas` set.
- A plain `http://` route — no TLS to anchor at all, out of this rule's scope.
- A CI token reference via `secrets.`/`env.`/a shell/GitHub-Actions expression.
- A PEM key committed OUTSIDE a tunnel-hinted path — that's the generic
  `hardcoded-private-key-in-source` guard's scope, not this one's.
- An empty placeholder Kubernetes Secret used as a `kubectl create secret` target.

## Tests

| Test | What it checks |
|---|---|
| `test_disable_ip_validation_fires` | `disable_ip_validation: true` — fires |
| `test_overly_broad_cidr_fires` | `0.0.0.0/0` in `allowed_ips` — fires |
| `test_narrow_allowed_ips_is_safe` | A real internal CIDR — silent |
| `test_https_route_with_no_trust_anchor_fires` | https route, no CA config — fires |
| `test_https_route_with_ca_file_is_safe` | `ca_file` set — silent |
| `test_http_route_not_flagged_for_trust_anchor` | Plain http route — out of scope |
| `test_ci_literal_tunnel_token_fires` | Literal token value in CI — fires |
| `test_ci_secrets_reference_is_safe` | `secrets.X` reference — silent |
| `test_committed_pem_key_under_tunnel_path_fires` | PEM key under `mcp-tunnel/` — fires |
| `test_pem_key_outside_tunnel_path_is_out_of_scope` | PEM key elsewhere — different guard's job |
| `test_k8s_tunnel_secret_with_literal_data_fires` | Named Secret, real data — fires |
| `test_k8s_empty_placeholder_secret_is_safe` | Empty Secret placeholder — silent |
| `test_block_list_before_disable_flag_still_fires` / `test_block_list_after_disable_flag_still_fires` / `test_indented_block_list_then_flag_fires` | Block-style list, either key order, either indent |
| `test_block_list_broad_cidr_fires_and_narrow_is_silent` | Block-list CIDR entries, both directions |
| `test_block_list_then_tls_mapping_still_parses` | A mapping after a block list still parses (no FP) |
| `test_findings_carry_line_numbers` | `path:line` location |
| `test_guard_not_applicable_without_mcp_feature` | `applies()` gates correctly |
| `test_mcp_tunnel_config_security_pragma_comment_suppresses_proxy_yaml`, `test_mcp_tunnel_config_security_pragma_quoted_in_a_string_does_not_suppress_proxy_yaml`, `test_mcp_tunnel_config_security_pragma_in_a_run_block_shell_comment_suppresses_ci`, `test_mcp_tunnel_config_security_pragma_quoted_in_a_string_does_not_suppress_ci`, `test_mcp_tunnel_config_security_pragma_comment_suppresses_k8s_secret`, `test_mcp_tunnel_config_security_pragma_quoted_in_a_string_does_not_suppress_k8s_secret` | A pragma quoted in a string literal or quoted scalar does not suppress; a real comment still opts the file out (#424 E6); a `#` shell comment inside a workflow `run: |` script still opts out |

## Known bypasses

- The tunnel-config filename/directory-hint vocabulary is fixed; a config with neither a
  recognized filename nor a recognized parent directory is invisible even with the right
  YAML shape.
- The tunnel-token env-var name vocabulary is a closed list.
- A Helm template that conditionally renders `disable_ip_validation` based on a values
  override is read as static YAML, not evaluated.
- **YAML parsing is a minimal, dependency-free subset parser, not a full YAML implementation**
  (agentsec ships zero runtime dependencies — a real `import yaml` would crash every user
  without PyYAML installed separately, a bug this guard shipped with briefly before being
  caught and fixed). Anchors/aliases, tags, multi-line scalars (`|`/`>`), and non-empty flow
  mappings (`{a: 1}`) are not supported and degrade the whole document to unparsed (a missed
  finding, never a crash or a false positive) rather than being approximated.
- Block-style sequences (`allowed_ips:` followed by `- item` lines, at the key's indent or
  deeper) ARE parsed, and sibling keys after the list are kept, so key order in the
  `upstream:` block does not change the result. A `- key: value` list item is read as a
  mapping; a nested block sequence inside a sequence item, and multi-line/folded scalars
  inside one, are not.
- Every finding carries `path:line` of the key that triggered it (the flag, the offending
  CIDR, the route, the credential line, the PEM header, or the `kind: Secret` line). For a
  multi-document manifest with several Secrets, the first `kind: Secret` line is reported.

## What this guard does NOT prove

Silence does not prove the tunnel is otherwise correctly configured — only that these three
specific, docs-named misconfiguration classes are absent from the files this guard
recognizes as tunnel configs.

# Citations

[1] agentsec checklist item `4-mcp-tunnel-config-security` (§4)
[2] Anthropic MCP Tunnels overview/reference/security docs (platform.claude.com, research preview 2026-05-19)
[3] CWE-918, CWE-295, CWE-798
[4] agent-audit-kit `mcp_tunnel.py`, rules AAK-MCP-TUNNEL-001/002/003
