"""Guard: an MCP Tunnels gateway config disables its own SSRF defense, forwards to an
HTTPS upstream with no trust anchor, or a tunnel credential/TLS key is hardcoded in the
repo or CI (checklist §4, new item; agent-audit-kit's `mcp_tunnel.py`
AAK-MCP-TUNNEL-001/002/003).

Anthropic MCP Tunnels (research preview, launched 2026-05-19) route outbound-only traffic
(cloudflared → tunnel edge → Anthropic Proxy) to private MCP servers via a gateway proxy
config. Per the official reference/security docs, the proxy's fields include
`upstream.allowed_ips` (its own documented "primary SSRF defense"),
`upstream.disable_ip_validation`, `upstream.tls.ca_file`/`include_system_cas`, and
`routes` mapping subdomains to `scheme://host:port` upstreams. The security page names the
tunnel token and the server TLS private key as customer-managed high-value secrets.

Three checks, each grounded directly in the official docs:

  1. **`ssrf-defense-disabled`** (CRITICAL, CWE-918): `upstream.disable_ip_validation:
     true`, or an `upstream.allowed_ips` entry covers a public-internet-sized CIDR
     (IPv4 prefix ≤ 7, IPv6 prefix ≤ 31, or the literal `0.0.0.0/0`/`::/0`).
  2. **`no-upstream-trust-anchor`** (HIGH, CWE-295): an `https://` upstream is configured in
     `routes` but neither `upstream.tls.ca_file` nor `upstream.tls.include_system_cas` is
     set — quoting the reference verbatim, "otherwise the proxy has no trust anchor for the
     upstream certificate."
  3. **`tunnel-credential-hardcoded`** (CRITICAL, CWE-798): a tunnel-token-shaped
     environment variable has a literal (non-`${...}`/non-`secrets.`/non-`env.`) value in a
     CI workflow file; a TLS private key (PEM header) is committed under an MCP-Tunnels-
     named path; or a Kubernetes `Secret` manifest named `mcp-tunnel`/`mcp-tunnel-token`/
     `mcp-tunnel-cert` is checked in with a non-empty literal `data`/`stringData` value.

A file is recognized as a tunnel proxy config when it is named
`config.yaml`/`config.yml`/`proxy.yaml`/`proxy.yml`/`values.yaml`/`values.yml`, sits under a
directory hinting at MCP Tunnels (`mcp-gateway`/`mcp-tunnel`/`gateway`/`tunnel`/...), AND
its parsed YAML carries the unambiguous `tunnel_domain` + `routes` shape (directly, or
nested under a Helm `gateway.config` wrapper). The minimal parser reads block-style `- item`
lists (at the key's indent or deeper) and keeps parsing the sibling keys after them, so the
order of keys inside `upstream:` does not matter. Every finding carries `path:line`.

Suppress an audited case with:

    # security: allow-mcp-tunnel-config-security
"""
from __future__ import annotations

import ipaddress
import re
from pathlib import Path
from typing import Any, Literal

from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import (
    CanaryPlant,
    Guard,
    comment_dialect_for,
    is_nonproduct_path,
    iter_files_named,
    pragma_present,
    read,
    rel,
)

_PRAGMA = "security: allow-mcp-tunnel-config-security"

# --- Minimal, dependency-free YAML-subset parser -----------------------------------------------
# agentsec ships with ZERO runtime dependencies (pyproject.toml `dependencies = []`; PyYAML is a
# dev-only extra). A module-level `import yaml` here would crash every `pipx install .` user with
# no PyYAML on their system the instant `agentsec.registry` imports this guard — the exact
# "zero-dependency" contract violation this project's own CLAUDE.md architecture section states as
# a hard rule. This parser covers exactly the shapes this guard's own config files use: nested
# block mappings (consistent indentation), inline flow lists (`['a', 'b']`), an inline empty flow
# mapping (`{}`), plain/quoted scalars, and `---`-separated multi-document files. It does NOT
# support anchors/tags, multi-line scalars, or non-empty flow mappings — those degrade to `None`/a
# skipped file rather than crashing, the same "never guess, never crash" contract the JSON-parsing
# guards in this codebase already follow.


def _strip_yaml_comment(line: str) -> str:
    quote: str | None = None
    for i, ch in enumerate(line):
        if quote:
            if ch == quote:
                quote = None
            continue
        if ch in "'\"":
            quote = ch
        elif ch == "#":
            return line[:i]
    return line


def _indent_of(line: str) -> int:
    return len(line) - len(line.lstrip(" "))


def _split_flow_items(inner: str) -> list[str]:
    items: list[str] = []
    buf: list[str] = []
    quote: str | None = None
    for ch in inner:
        if quote:
            buf.append(ch)
            if ch == quote:
                quote = None
            continue
        if ch in "'\"":
            quote = ch
            buf.append(ch)
        elif ch == ",":
            items.append("".join(buf).strip())
            buf = []
        else:
            buf.append(ch)
    if buf:
        items.append("".join(buf).strip())
    return [i for i in items if i]


def _parse_yaml_scalar(raw: str) -> Any:
    s = raw.strip()
    if s in ("", "~", "null", "Null", "NULL"):
        return None
    if s in ("true", "True", "TRUE"):
        return True
    if s in ("false", "False", "FALSE"):
        return False
    if s.startswith("{") and s.endswith("}"):
        return {} if not s[1:-1].strip() else None  # non-empty flow mappings: unsupported
    if s.startswith("[") and s.endswith("]"):
        return [_parse_yaml_scalar(i) for i in _split_flow_items(s[1:-1])]
    if len(s) >= 2 and s[0] == s[-1] and s[0] in "'\"":
        return s[1:-1]
    try:
        return int(s)
    except ValueError:
        pass
    try:
        return float(s)
    except ValueError:
        pass
    return s


def _parse_block_sequence(lines: list[str], idx: int, indent: int) -> tuple[list[Any], int]:
    """Consume a block-style `- item` list whose dashes sit at exactly `indent`; return the items
    and the index of the first line AFTER the list (so the enclosing mapping keeps parsing its
    remaining sibling keys, whatever their order). A `- key: value` item is parsed as a mapping
    (its continuation lines are the ones indented deeper than the dash)."""
    items: list[Any] = []
    n = len(lines)
    while idx < n:
        line = _strip_yaml_comment(lines[idx])
        if not line.strip():
            idx += 1
            continue
        if _indent_of(line) != indent:
            break
        content = line.strip()
        if content != "-" and not content.startswith("- "):
            break
        item = content[1:].strip()
        idx += 1
        if not item:
            items.append(None)
            continue
        if ":" in item and not item.startswith(("'", '"', "[", "{")):
            # `- key: value` opens a mapping whose keys align with `key` (dash indent + 2).
            item_indent = indent + (len(content) - len(content[1:].lstrip()))
            lines[idx - 1] = " " * item_indent + item
            child, idx = _parse_yaml_mapping(lines, idx - 1, item_indent)
            items.append(child)
        else:
            items.append(_parse_yaml_scalar(item))
    return items, idx


def _parse_yaml_mapping(lines: list[str], idx: int, indent: int) -> tuple[dict[str, Any], int]:
    mapping: dict[str, Any] = {}
    n = len(lines)
    while idx < n:
        line = _strip_yaml_comment(lines[idx])
        if not line.strip():
            idx += 1
            continue
        cur_indent = _indent_of(line)
        if cur_indent != indent:
            break
        content = line.strip()
        if content.startswith("- ") or content == "-" or ":" not in content:
            break
        key_part, _, rest = content.partition(":")
        key = key_part.strip().strip("'\"")
        rest = rest.strip()
        idx += 1
        if rest:
            mapping[key] = _parse_yaml_scalar(rest)
            continue
        next_real = idx
        while next_real < n and not _strip_yaml_comment(lines[next_real]).strip():
            next_real += 1
        if next_real >= n:
            mapping[key] = None
            continue
        nxt = _strip_yaml_comment(lines[next_real])
        nxt_indent = _indent_of(nxt)
        nxt_content = nxt.strip()
        is_seq = nxt_content == "-" or nxt_content.startswith("- ")
        if is_seq and nxt_indent >= indent:
            # a block list may sit at the key's own indent (`key:` / `- a`) or deeper
            seq, idx = _parse_block_sequence(lines, next_real, nxt_indent)
            mapping[key] = seq
        elif nxt_indent > indent:
            child, idx = _parse_yaml_mapping(lines, next_real, nxt_indent)
            mapping[key] = child
        else:
            mapping[key] = None
    return mapping, idx


def _parse_simple_yaml(text: str) -> Any:
    """One YAML document -> nested dict/list/scalar, or `None` on anything this minimal parser
    doesn't understand (never raises)."""
    try:
        lines = text.splitlines()
        idx = 0
        n = len(lines)
        while idx < n and not _strip_yaml_comment(lines[idx]).strip():
            idx += 1
        if idx >= n:
            return None
        base_indent = _indent_of(_strip_yaml_comment(lines[idx]))
        data, _ = _parse_yaml_mapping(lines, idx, base_indent)
        return data
    except Exception:  # noqa: BLE001 - a parse failure degrades to "skip", never a crash
        return None


def _parse_simple_yaml_all(text: str) -> list[Any]:
    """`---`-separated multi-document YAML -> a list of parsed documents."""
    docs: list[str] = []
    current: list[str] = []
    for line in text.splitlines():
        if line.strip() == "---":
            if current:
                docs.append("\n".join(current))
            current = []
            continue
        current.append(line)
    if current:
        docs.append("\n".join(current))
    return [_parse_simple_yaml(d) for d in docs]

_TUNNEL_PROXY_FILENAMES = ("config.yaml", "config.yml", "proxy.yaml", "proxy.yml", "values.yaml", "values.yml")
_TUNNEL_PARENT_DIR_HINTS = (
    "mcp-gateway", "mcp-tunnel", "mcp_tunnel", "mcp_gateway", "mcp-tunnels", "tunnel", "gateway",
)
_CI_FILE_GLOBS = (
    ".github/workflows/*.yml", ".github/workflows/*.yaml",
    ".gitlab-ci.yml", "azure-pipelines.yml", "azure-pipelines.yaml",
    ".circleci/config.yml", ".circleci/config.yaml",
)
_TUNNEL_TOKEN_KEY_RE = re.compile(
    r"^(?:MCP[_-]?TUNNEL[_-]?TOKEN|TUNNEL[_-]?TOKEN|ANTHROPIC[_-]?TUNNEL[_-]?TOKEN|"
    r"TUNNELS?[_-]?API[_-]?TOKEN|ANTHROPIC[_-]?IDENTITY[_-]?TOKEN)$",
    re.IGNORECASE,
)
_TOKEN_LITERAL_LINE_RE = re.compile(
    r"""^\s*(?P<key>[A-Z][A-Z0-9_-]+)\s*[:=]\s*(?P<q>['\"]?)(?P<val>[^\s'\"\$\{][^\s'\"]*)(?P=q)\s*$""",
    re.VERBOSE,
)
_PEM_PRIVATE_KEY_RE = re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY-----")
_K8S_TUNNEL_SECRET_NAMES = ("mcp-tunnel", "mcp-tunnel-token", "mcp-tunnel-cert")

_STANDARDS_SSRF = ["CWE-918", "OWASP:A10"]
_STANDARDS_TLS = ["CWE-295", "OWASP:A02"]
_STANDARDS_CRED = ["CWE-798", "OWASP:A02"]


def _loc(r: str, raw: str, needle: str) -> str:
    """`path:line` of the first line containing `needle` (bare `path` when it cannot be found)."""
    for i, line in enumerate(raw.splitlines(), 1):
        if needle in line:
            return f"{r}:{i}"
    return r


def _looks_like_tunnel_proxy_config(data: Any) -> bool:
    if not isinstance(data, dict):
        return False
    if "tunnel_domain" in data and "routes" in data:
        return True
    gw = data.get("gateway")
    if isinstance(gw, dict):
        inner = gw.get("config")
        if isinstance(inner, dict) and "tunnel_domain" in inner and "routes" in inner:
            return True
    return False


def _unwrap_proxy_config(data: Any) -> dict[str, Any] | None:
    if not isinstance(data, dict):
        return None
    if "tunnel_domain" in data and "routes" in data:
        return data
    gw = data.get("gateway")
    if isinstance(gw, dict):
        inner = gw.get("config")
        if isinstance(inner, dict) and "tunnel_domain" in inner and "routes" in inner:
            return inner
    return None


def _path_hints_tunnel(p: Path, root: Path) -> bool:
    try:
        parts = {part.lower() for part in p.relative_to(root).parts}
    except ValueError:
        parts = {part.lower() for part in p.parts}
    return bool(parts & set(_TUNNEL_PARENT_DIR_HINTS))


def _is_overly_broad_cidr(value: str) -> tuple[bool, str]:
    s = value.strip()
    if not s:
        return False, ""
    if s in ("0.0.0.0/0",) or s in ("::/0",):
        return True, f"matches the entire public internet ({s})"
    try:
        net = ipaddress.ip_network(s, strict=False)
    except (ValueError, TypeError):
        return False, ""
    if isinstance(net, ipaddress.IPv4Network) and net.prefixlen <= 7:
        return True, f"IPv4 /{net.prefixlen} covers {net.num_addresses:,} addresses"
    if isinstance(net, ipaddress.IPv6Network) and net.prefixlen <= 31:
        return True, f"IPv6 /{net.prefixlen} covers far more than a private network"
    return False, ""


class McpTunnelConfigSecurityGuard(Guard):
    id = "mcp-tunnel-config-security"
    title = "MCP Tunnels gateway config disables SSRF defense, lacks a TLS trust anchor, or leaks credentials"
    area = "AI agent"

    # mcp-gateway/config.yaml: disable_ip_validation: true -> fires
    # mcp-tunnel-config-security/ssrf-defense-disabled.
    canary_plant = CanaryPlant(
        files={
            "mcp-gateway/config.yaml": (
                "tunnel_domain: canary.example.com\n"
                "routes:\n"
                "  app: https://internal.example.com:8443\n"
                "upstream:\n"
                "  disable_ip_validation: true\n"
            ),
        },
        expects=frozenset({
            "mcp-tunnel-config-security/ssrf-defense-disabled",
        }),
    )

    def applies(self, profile: StackProfile) -> bool:
        return "mcp" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []

        for p in iter_files_named(root, "*.yaml", "*.yml"):
            r = rel(root, p)
            if is_nonproduct_path(r, profile.archive_segments):
                continue
            if p.name.lower() not in _TUNNEL_PROXY_FILENAMES and not _path_hints_tunnel(p, root):
                continue
            raw = read(p)
            if not raw or pragma_present(_PRAGMA, raw, dialect="yaml"):
                continue
            data = _parse_simple_yaml(raw)
            if not _looks_like_tunnel_proxy_config(data):
                continue
            cfg = _unwrap_proxy_config(data)
            if cfg is None:
                continue
            out.extend(self._check_ssrf_defense(cfg, r, raw))
            out.extend(self._check_trust_anchor(cfg, r, raw))

        out.extend(self._check_ci_tokens(root, profile))
        out.extend(self._check_committed_pem_keys(root, profile))
        out.extend(self._check_k8s_secrets(root, profile))
        return out

    def _check_ssrf_defense(self, cfg: dict[str, Any], r: str, raw: str) -> list[Finding]:
        out: list[Finding] = []
        upstream = cfg.get("upstream")
        if not isinstance(upstream, dict):
            return out
        if upstream.get("disable_ip_validation") is True:
            out.append(self._finding(
                _loc(r, raw, "disable_ip_validation"), "critical", "ssrf-defense-disabled", _STANDARDS_SSRF,
                "`upstream.disable_ip_validation: true` — the proxy's own documented "
                "primary SSRF defense is turned off.",
            ))
        allowed = upstream.get("allowed_ips")
        if isinstance(allowed, list):
            for item in allowed:
                if not isinstance(item, str):
                    continue
                broad, reason = _is_overly_broad_cidr(item)
                if broad:
                    out.append(self._finding(
                        _loc(r, raw, item), "critical", "ssrf-defense-disabled", _STANDARDS_SSRF,
                        f"`upstream.allowed_ips` entry {item!r} is overly broad — {reason}.",
                    ))
        return out

    def _check_trust_anchor(self, cfg: dict[str, Any], r: str, raw: str) -> list[Finding]:
        out: list[Finding] = []
        routes = cfg.get("routes")
        if not isinstance(routes, dict):
            return out
        upstream = cfg.get("upstream") or {}
        upstream_tls = upstream.get("tls") if isinstance(upstream, dict) else None
        has_ca_file = bool(
            isinstance(upstream_tls, dict)
            and isinstance(upstream_tls.get("ca_file"), str)
            and upstream_tls.get("ca_file", "").strip()
        )
        has_system_cas = isinstance(upstream_tls, dict) and upstream_tls.get("include_system_cas") is True
        if has_ca_file or has_system_cas:
            return out
        for subdomain, upstream_url in routes.items():
            if isinstance(upstream_url, str) and upstream_url.strip().lower().startswith("https://"):
                out.append(self._finding(
                    _loc(r, raw, str(subdomain)), "high", "no-upstream-trust-anchor", _STANDARDS_TLS,
                    f"Route {subdomain!r} forwards to {upstream_url} but neither "
                    "`upstream.tls.ca_file` nor `upstream.tls.include_system_cas` is set "
                    "— the proxy has no trust anchor for the upstream certificate.",
                ))
        return out

    def _check_ci_tokens(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []
        for glob in _CI_FILE_GLOBS:
            for p in root.glob(glob):
                if not p.is_file():
                    continue
                r = rel(root, p)
                if is_nonproduct_path(r, profile.archive_segments, credential_scan=True):
                    continue
                raw = read(p)
                # `hash`, not `yaml` (#1000 D1): a CI file's `run: |` script is shell, so a `#`
                # comment inside it opts out as it always has; a quoted scalar is still content.
                if not raw or pragma_present(_PRAGMA, raw, dialect="hash"):
                    continue
                for lineno, line in enumerate(raw.splitlines(), 1):
                    stripped = line.strip()
                    if not stripped or stripped.startswith("#"):
                        continue
                    m = _TOKEN_LITERAL_LINE_RE.match(line)
                    if not m:
                        continue
                    key = m.group("key")
                    if not _TUNNEL_TOKEN_KEY_RE.match(key):
                        continue
                    val = m.group("val")
                    if val.startswith(("${{", "$(", "$")) or val in ("true", "false", "null", "~"):
                        continue
                    if "secrets." in val or "env." in val:
                        continue
                    out.append(self._finding(
                        f"{r}:{lineno}", "critical", "tunnel-credential-hardcoded", _STANDARDS_CRED,
                        f"Tunnel credential env var `{key}` has a literal value in CI "
                        "config — must be sourced from a secrets store.",
                    ))
        return out

    def _check_committed_pem_keys(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []
        # The shared walker, not `root.rglob`, so a vendored `.venv/.../gateway/*.pem` or a nested
        # worktree is never reported (#1042). `respect_gitignore=False` keeps a gitignored key in
        # scope: a private key on disk under a tunnel path is the finding, ignored or not.
        for p in iter_files_named(root, "*", respect_gitignore=False):
            if not p.is_file() or not _path_hints_tunnel(p, root):
                continue
            r = rel(root, p)
            if is_nonproduct_path(r, profile.archive_segments, credential_scan=True):
                continue
            try:
                if p.stat().st_size > 100_000:
                    continue
            except OSError:
                continue
            raw = read(p)
            pem = _PEM_PRIVATE_KEY_RE.search(raw) if raw else None
            if pem is None or pragma_present(_PRAGMA, raw, dialect=comment_dialect_for(p)):
                continue
            out.append(self._finding(
                f"{r}:{raw.count(chr(10), 0, pem.start()) + 1}", "critical", "tunnel-credential-hardcoded", _STANDARDS_CRED,
                f"TLS private key committed under MCP-Tunnels path {r!r} — the server "
                "TLS key is a high-value secret that must be protected at rest.",
            ))
        return out

    def _check_k8s_secrets(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []
        for p in iter_files_named(root, "*.yaml", "*.yml"):
            r = rel(root, p)
            if is_nonproduct_path(r, profile.archive_segments, credential_scan=True):
                continue
            raw = read(p)
            if not raw or "kind: Secret" not in raw or pragma_present(_PRAGMA, raw, dialect="yaml"):
                continue
            docs = _parse_simple_yaml_all(raw)
            for doc in docs:
                if not isinstance(doc, dict) or doc.get("kind") != "Secret":
                    continue
                meta = doc.get("metadata") or {}
                if not isinstance(meta, dict):
                    continue
                name = str(meta.get("name", "")).lower()
                if name not in _K8S_TUNNEL_SECRET_NAMES:
                    continue
                data = doc.get("data") or doc.get("stringData") or {}
                if not isinstance(data, dict) or not any(
                    isinstance(v, str) and v.strip() for v in data.values()
                ):
                    continue
                out.append(self._finding(
                    _loc(r, raw, "kind: Secret"), "critical", "tunnel-credential-hardcoded", _STANDARDS_CRED,
                    f"Kubernetes Secret {name!r} for MCP Tunnels is checked in with "
                    "literal data values — credentials must be created out-of-band.",
                ))
        return out

    def _finding(
        self,
        r: str,
        severity: Literal["critical", "high"],
        rule_suffix: str,
        standards: list[str],
        message: str,
    ) -> Finding:
        return Finding(
            check_id=self.id,
            severity=severity,
            title=self.title,
            location=r,
            message=message,
            remediation=(
                "Re-enable IP validation and scope `allowed_ips` to real internal "
                "ranges; set `upstream.tls.ca_file` or `include_system_cas` for every "
                "https upstream; and move tunnel tokens/TLS keys to a secrets manager, "
                "never a literal value in a config, CI file, or committed manifest."
            ),
            rule=f"mcp-tunnel-config-security/{rule_suffix}",
            standards=list(standards),
        )
