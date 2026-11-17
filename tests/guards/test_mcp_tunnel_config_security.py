"""Tests for McpTunnelConfigSecurityGuard — planted-violation + FP-bait per rule."""
from __future__ import annotations

import pytest

from agentsec.findings import Finding
from agentsec.guards.mcp_tunnel_config_security import McpTunnelConfigSecurityGuard
from tests.guards._common import *  # noqa: F401,F403


def _mcp_prof(root: Path) -> StackProfile:
    return mkprofile(root, features={"mcp", "python"}, python_dirs=["."])


# ── ssrf-defense-disabled ─────────────────────────────────────────────────

def test_disable_ip_validation_fires(tmp_path: Path) -> None:
    d = tmp_path / "mcp-gateway"
    d.mkdir()
    (d / "config.yaml").write_text(
        "tunnel_domain: x.example.com\n"
        "routes:\n  app: http://internal:8080\n"
        "upstream:\n  disable_ip_validation: true\n",
        encoding="utf-8",
    )
    findings = McpTunnelConfigSecurityGuard().run(tmp_path, _mcp_prof(tmp_path))
    hit = next(f for f in findings if f.rule == "mcp-tunnel-config-security/ssrf-defense-disabled")
    assert hit.severity == "critical"


def test_overly_broad_cidr_fires(tmp_path: Path) -> None:
    d = tmp_path / "mcp-gateway"
    d.mkdir()
    (d / "config.yaml").write_text(
        "tunnel_domain: x.example.com\n"
        "routes:\n  app: http://internal:8080\n"
        "upstream:\n  allowed_ips: ['0.0.0.0/0']\n",
        encoding="utf-8",
    )
    findings = McpTunnelConfigSecurityGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert any(f.rule == "mcp-tunnel-config-security/ssrf-defense-disabled" for f in findings)


def test_narrow_allowed_ips_is_safe(tmp_path: Path) -> None:
    """FP-bait: a real internal-sized CIDR is safe."""
    d = tmp_path / "mcp-gateway"
    d.mkdir()
    (d / "config.yaml").write_text(
        "tunnel_domain: x.example.com\n"
        "routes:\n  app: http://internal:8080\n"
        "upstream:\n  allowed_ips: ['10.0.0.0/24']\n",
        encoding="utf-8",
    )
    findings = McpTunnelConfigSecurityGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert not any(f.rule == "mcp-tunnel-config-security/ssrf-defense-disabled" for f in findings)


# ── no-upstream-trust-anchor ───────────────────────────────────────────────

def test_https_route_with_no_trust_anchor_fires(tmp_path: Path) -> None:
    d = tmp_path / "mcp-gateway"
    d.mkdir()
    (d / "config.yaml").write_text(
        "tunnel_domain: x.example.com\n"
        "routes:\n  app: https://internal.example.com:8443\n",
        encoding="utf-8",
    )
    findings = McpTunnelConfigSecurityGuard().run(tmp_path, _mcp_prof(tmp_path))
    hit = next(f for f in findings if f.rule == "mcp-tunnel-config-security/no-upstream-trust-anchor")
    assert hit.severity == "high"


def test_https_route_with_ca_file_is_safe(tmp_path: Path) -> None:
    d = tmp_path / "mcp-gateway"
    d.mkdir()
    (d / "config.yaml").write_text(
        "tunnel_domain: x.example.com\n"
        "routes:\n  app: https://internal.example.com:8443\n"
        "upstream:\n  tls:\n    ca_file: /etc/certs/ca.pem\n",
        encoding="utf-8",
    )
    findings = McpTunnelConfigSecurityGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert not any(f.rule == "mcp-tunnel-config-security/no-upstream-trust-anchor" for f in findings)


def test_http_route_not_flagged_for_trust_anchor(tmp_path: Path) -> None:
    """FP-bait: a plain http:// route has no TLS to anchor at all."""
    d = tmp_path / "mcp-gateway"
    d.mkdir()
    (d / "config.yaml").write_text(
        "tunnel_domain: x.example.com\nroutes:\n  app: http://internal:8080\n",
        encoding="utf-8",
    )
    findings = McpTunnelConfigSecurityGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert not any(f.rule == "mcp-tunnel-config-security/no-upstream-trust-anchor" for f in findings)


# ── tunnel-credential-hardcoded ────────────────────────────────────────────

def test_ci_literal_tunnel_token_fires(tmp_path: Path) -> None:
    ci = tmp_path / ".github" / "workflows"
    ci.mkdir(parents=True)
    (ci / "deploy.yml").write_text(
        "jobs:\n  deploy:\n    steps:\n      - run: echo hi\n"
        "MCP_TUNNEL_TOKEN=abcdef1234567890\n",
        encoding="utf-8",
    )
    findings = McpTunnelConfigSecurityGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert any(f.rule == "mcp-tunnel-config-security/tunnel-credential-hardcoded" for f in findings)


def test_ci_secrets_reference_is_safe(tmp_path: Path) -> None:
    ci = tmp_path / ".github" / "workflows"
    ci.mkdir(parents=True)
    (ci / "deploy.yml").write_text(
        "MCP_TUNNEL_TOKEN=secrets.MCP_TUNNEL_TOKEN\n",
        encoding="utf-8",
    )
    findings = McpTunnelConfigSecurityGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert not any(f.rule == "mcp-tunnel-config-security/tunnel-credential-hardcoded" for f in findings)


def test_committed_pem_key_under_tunnel_path_fires(tmp_path: Path) -> None:
    d = tmp_path / "mcp-tunnel"
    d.mkdir()
    (d / "server.key").write_text(
        "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA\n-----END RSA PRIVATE KEY-----\n",
        encoding="utf-8",
    )
    findings = McpTunnelConfigSecurityGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert any(f.rule == "mcp-tunnel-config-security/tunnel-credential-hardcoded" for f in findings)


def test_pem_key_outside_tunnel_path_is_out_of_scope(tmp_path: Path) -> None:
    """FP-bait: a PEM key elsewhere in the repo is a different guard's job
    (hardcoded-private-key-in-source), not this one's tunnel-scoped check."""
    (tmp_path / "server.key").write_text(
        "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA\n-----END RSA PRIVATE KEY-----\n",
        encoding="utf-8",
    )
    findings = McpTunnelConfigSecurityGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert not any(f.rule == "mcp-tunnel-config-security/tunnel-credential-hardcoded" for f in findings)


def test_k8s_tunnel_secret_with_literal_data_fires(tmp_path: Path) -> None:
    (tmp_path / "secret.yaml").write_text(
        "kind: Secret\napiVersion: v1\nmetadata:\n  name: mcp-tunnel-token\n"
        "data:\n  token: YWJjZGVmZ2hpams=\n",
        encoding="utf-8",
    )
    findings = McpTunnelConfigSecurityGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert any(f.rule == "mcp-tunnel-config-security/tunnel-credential-hardcoded" for f in findings)


def test_k8s_empty_placeholder_secret_is_safe(tmp_path: Path) -> None:
    """FP-bait: an empty Secret used as a kubectl-create target is not a real leak."""
    (tmp_path / "secret.yaml").write_text(
        "kind: Secret\napiVersion: v1\nmetadata:\n  name: mcp-tunnel-token\ndata: {}\n",
        encoding="utf-8",
    )
    findings = McpTunnelConfigSecurityGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert not any(f.rule == "mcp-tunnel-config-security/tunnel-credential-hardcoded" for f in findings)


def test_guard_not_applicable_without_mcp_feature(tmp_path: Path) -> None:
    prof = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    assert McpTunnelConfigSecurityGuard().applies(prof) is False


# ── block-style sequences: key order must not matter ──────────────────────

_TUNNEL_HEAD = "tunnel_domain: x.example.com\nroutes:\n  app: http://internal:8080\nupstream:\n"
_SSRF = "mcp-tunnel-config-security/ssrf-defense-disabled"


def _run_cfg(tmp_path: Path, body: str) -> list[Finding]:
    d = tmp_path / "mcp-gateway"
    d.mkdir(exist_ok=True)
    (d / "config.yaml").write_text(_TUNNEL_HEAD + body, encoding="utf-8")
    return McpTunnelConfigSecurityGuard().run(tmp_path, _mcp_prof(tmp_path))


def test_block_list_before_disable_flag_still_fires(tmp_path: Path) -> None:
    """The block-style `allowed_ips` list used to unwind the mapping and silently drop the
    CRITICAL that followed it."""
    findings = _run_cfg(tmp_path, "  allowed_ips:\n  - 10.0.0.0/8\n  disable_ip_validation: true\n")
    hit = [f for f in findings if f.rule == _SSRF]
    assert len(hit) == 1 and hit[0].severity == "critical"
    assert hit[0].location.replace("\\", "/") == "mcp-gateway/config.yaml:7"  # the `disable_ip_validation` line


def test_block_list_after_disable_flag_still_fires(tmp_path: Path) -> None:
    findings = _run_cfg(tmp_path, "  disable_ip_validation: true\n  allowed_ips:\n  - 10.0.0.0/8\n")
    assert any(f.rule == _SSRF for f in findings)


def test_indented_block_list_then_flag_fires(tmp_path: Path) -> None:
    findings = _run_cfg(tmp_path, "  allowed_ips:\n    - 10.0.0.0/8\n  disable_ip_validation: true\n")
    assert any(f.rule == _SSRF for f in findings)


def test_block_list_broad_cidr_fires_and_narrow_is_silent(tmp_path: Path) -> None:
    broad = _run_cfg(tmp_path, "  allowed_ips:\n    - 10.0.0.0/24\n    - 0.0.0.0/0\n")
    assert sum(1 for f in broad if f.rule == _SSRF) == 1
    narrow = _run_cfg(tmp_path, "  allowed_ips:\n    - 10.0.0.0/24\n    - 192.168.0.0/16\n")
    assert not any(f.rule == _SSRF for f in narrow)


def test_block_list_then_tls_mapping_still_parses(tmp_path: Path) -> None:
    """FP-bait: a block list followed by a nested `tls` mapping keeps the trust anchor visible."""
    d = tmp_path / "mcp-gateway"
    d.mkdir()
    (d / "config.yaml").write_text(
        "tunnel_domain: x.example.com\nroutes:\n  app: https://internal:8443\n"
        "upstream:\n  allowed_ips:\n  - 10.0.0.0/8\n  tls:\n    ca_file: /etc/ca.pem\n",
        encoding="utf-8",
    )
    findings = McpTunnelConfigSecurityGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert not any(f.rule.endswith("no-upstream-trust-anchor") for f in findings)


def test_findings_carry_line_numbers(tmp_path: Path) -> None:
    findings = _run_cfg(tmp_path, "  disable_ip_validation: true\n")
    hit = next(f for f in findings if f.rule == _SSRF)
    assert hit.location.replace("\\", "/") == "mcp-gateway/config.yaml:5"


# ── #424 E6 (#1000): the pragma counts only as a real comment ─────────────

_CRED = "mcp-tunnel-config-security/tunnel-credential-hardcoded"
_PRAGMA_COMMENT = "# security: allow-mcp-tunnel-config-security"
_PRAGMA_QUOTED = '"opt out with # security: allow-mcp-tunnel-config-security"'
# The `test_disable_ip_validation_fires` proxy config and the `test_k8s_tunnel_secret_with_literal_data_fires`
# Secret, both firing as written.
_PROXY_CFG = (
    "tunnel_domain: x.example.com\n"
    "routes:\n  app: http://internal:8080\n"
    "upstream:\n  disable_ip_validation: true\n"
)
_K8S_HEAD = "kind: Secret\napiVersion: v1\nmetadata:\n  name: mcp-tunnel-token\n"
_K8S_DATA = "data:\n  token: YWJjZGVmZ2hpams=\n"


def _run_file(root: Path, rel_path: str, body: str) -> list[Finding]:
    p = root / rel_path
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(body, encoding="utf-8")
    return McpTunnelConfigSecurityGuard().run(root, _mcp_prof(root))


def test_mcp_tunnel_config_security_pragma_comment_suppresses_proxy_yaml(tmp_path: Path) -> None:
    # #424 E6 (#1000): a real `#` YAML comment still opts the whole proxy config out; the same
    # config without it fires, so the suppression is never vacuous.
    cfg = "mcp-gateway/config.yaml"
    assert [f.rule for f in _run_file(tmp_path / "fires", cfg, _PROXY_CFG)] == [_SSRF]
    assert _run_file(tmp_path / "opted-out", cfg, _PRAGMA_COMMENT + "\n" + _PROXY_CFG) == []


def test_mcp_tunnel_config_security_pragma_quoted_in_a_string_does_not_suppress_proxy_yaml(
    tmp_path: Path,
) -> None:
    # #424 E6 (#1000): the proxy config reads the `yaml` comment view, so a quoted scalar quoting the
    # pragma is content. Only a real `#` comment (`..._pragma_comment_suppresses_proxy_yaml`) opts out.
    body = f"description: {_PRAGMA_QUOTED}\n" + _PROXY_CFG
    findings = _run_file(tmp_path, "mcp-gateway/config.yaml", body)
    assert [f.rule for f in findings] == [_SSRF]


def test_mcp_tunnel_config_security_pragma_in_a_run_block_shell_comment_suppresses_ci(tmp_path: Path) -> None:
    # #424 E6 (#1000) D1: the CI-file site reads `hash`, not `yaml`, so a `#` shell comment inside a
    # `run: |` script still opts out (CLAUDE.md rule 4: an opt-out the user already wrote must keep
    # working). The same workflow without the comment fires.
    def workflow(pragma: str) -> str:
        return (
            "jobs:\n  deploy:\n    runs-on: ubuntu-latest\n    steps:\n"
            "      - run: |\n" + pragma +
            "          MCP_TUNNEL_TOKEN=abcdef1234567890\n"
            "          ./deploy.sh\n"
        )

    wf = ".github/workflows/deploy.yml"
    assert [f.rule for f in _run_file(tmp_path / "fires", wf, workflow(""))] == [_CRED]
    assert _run_file(tmp_path / "opted-out", wf, workflow(f"          {_PRAGMA_COMMENT}\n")) == []


def test_mcp_tunnel_config_security_pragma_quoted_in_a_string_does_not_suppress_ci(tmp_path: Path) -> None:
    # #424 E6 (#1000) D1: `hash` is quote-aware, so a quoted step `name:` quoting the pragma is not a
    # comment; the literal tunnel token from `test_ci_literal_tunnel_token_fires` still fires.
    findings = _run_file(
        tmp_path,
        ".github/workflows/deploy.yml",
        "jobs:\n  deploy:\n    steps:\n      - run: echo hi\n"
        f"      - name: {_PRAGMA_QUOTED}\n        run: ./deploy.sh\n"
        "MCP_TUNNEL_TOKEN=abcdef1234567890\n",
    )
    assert [f.rule for f in findings] == [_CRED]


def test_mcp_tunnel_config_security_pragma_comment_suppresses_k8s_secret(tmp_path: Path) -> None:
    # #424 E6 (#1000): a real `#` YAML comment still opts a k8s Secret manifest out; the same
    # manifest without it fires, so the suppression is never vacuous.
    assert [f.rule for f in _run_file(tmp_path / "fires", "secret.yaml", _K8S_HEAD + _K8S_DATA)] == [_CRED]
    opted_out = _PRAGMA_COMMENT + "\n" + _K8S_HEAD + _K8S_DATA
    assert _run_file(tmp_path / "opted-out", "secret.yaml", opted_out) == []


def test_mcp_tunnel_config_security_pragma_quoted_in_a_string_does_not_suppress_k8s_secret(
    tmp_path: Path,
) -> None:
    # #424 E6 (#1000): the k8s Secret site reads the `yaml` view, so an annotation value quoting the
    # pragma is content. Only a real `#` comment (`..._pragma_comment_suppresses_k8s_secret`) opts out.
    body = _K8S_HEAD + f"  annotations:\n    note: {_PRAGMA_QUOTED}\n" + _K8S_DATA
    findings = _run_file(tmp_path, "secret.yaml", body)
    assert [f.rule for f in findings] == [_CRED]


# ── #1042: the PEM pass enumerates through the shared walker ──────────────
_PEM = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA\n-----END RSA PRIVATE KEY-----\n"


def _key_paths(root: Path) -> set[str]:
    findings = McpTunnelConfigSecurityGuard().run(root, _mcp_prof(root))
    return {f.location.replace("\\", "/").rsplit(":", 1)[0] for f in findings if f.rule == _CRED}


@pytest.mark.parametrize("prefix", _VENDORED_PREFIXES)
def test_vendored_tunnel_key_is_never_scanned_but_first_party_still_fires(tmp_path: Path, prefix: str) -> None:
    """The PEM pass walked the whole repo with `root.rglob("*")`, so a test key a dependency ships
    under its own `gateway/` dir in `.venv/site-packages` raised a CRITICAL. A first-party tunnel key
    must still fire."""
    _plant(tmp_path, f"{prefix}/mcp-tunnel/server.key", _PEM)
    _plant(tmp_path, "mcp-tunnel/server.key", _PEM)
    assert _key_paths(tmp_path) == {"mcp-tunnel/server.key"}


def test_gitignored_tunnel_key_still_fires(tmp_path: Path) -> None:
    """The walker swap must not narrow the gitignore axis (`respect_gitignore=False`): the old walk
    saw a gitignored key, and a private key on disk under a tunnel path is the finding either way."""
    _plant(tmp_path, ".gitignore", "mcp-tunnel/server.key\n")
    _plant(tmp_path, "mcp-tunnel/server.key", _PEM)
    assert _key_paths(tmp_path) == {"mcp-tunnel/server.key"}


def test_tunnel_key_inside_a_nested_worktree_is_not_reported(tmp_path: Path) -> None:
    """A linked worktree (its `.git` is a file) is another branch's checkout, not this tree."""
    _plant(tmp_path, "wt/.git", "gitdir: /elsewhere/.git/worktrees/wt\n")
    _plant(tmp_path, "wt/mcp-tunnel/server.key", _PEM)
    _plant(tmp_path, "mcp-tunnel/server.key", _PEM)
    assert _key_paths(tmp_path) == {"mcp-tunnel/server.key"}
