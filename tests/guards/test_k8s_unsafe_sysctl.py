from __future__ import annotations

from agentsec.guards.k8s_unsafe_sysctl import K8sUnsafeSysctlGuard
from tests.guards._common import *  # noqa: F401,F403


def _k8s_prof(root: Path) -> StackProfile:
    return mkprofile(root, features={"k8s"})


def test_k8s_unsafe_sysctl_fires_kernel_prefix(tmp_path: Path) -> None:
    (tmp_path / "pod.yaml").write_text(
        "apiVersion: v1\nkind: Pod\nmetadata:\n  name: bad\nspec:\n"
        "  securityContext:\n    sysctls:\n    - name: kernel.msgmax\n      value: \"65536\"\n"
        "  containers:\n  - name: app\n    image: nginx\n",
        encoding="utf-8",
    )
    findings = K8sUnsafeSysctlGuard().run(tmp_path, _k8s_prof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "k8s-unsafe-sysctl/kernel.msgmax"
    assert findings[0].severity == "high"


def test_k8s_unsafe_sysctl_fires_net_prefix_not_on_safe_list(tmp_path: Path) -> None:
    (tmp_path / "pod.yaml").write_text(
        "apiVersion: v1\nkind: Pod\nmetadata:\n  name: bad\nspec:\n"
        "  securityContext:\n    sysctls:\n    - name: net.core.somaxconn\n      value: \"1024\"\n"
        "  containers:\n  - name: app\n    image: nginx\n",
        encoding="utf-8",
    )
    findings = K8sUnsafeSysctlGuard().run(tmp_path, _k8s_prof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "k8s-unsafe-sysctl/net.core.somaxconn"


def test_k8s_unsafe_sysctl_fires_multiple_entries_independently(tmp_path: Path) -> None:
    # Adversarial/bypass case: two unsafe sysctls in the same list, one safe one mixed in --
    # each unsafe entry must fire its own finding and the safe one must not appear at all.
    (tmp_path / "pod.yaml").write_text(
        "apiVersion: v1\nkind: Pod\nmetadata:\n  name: bad\nspec:\n"
        "  securityContext:\n    sysctls:\n"
        "    - name: kernel.msgmax\n      value: \"65536\"\n"
        "    - name: net.ipv4.tcp_syncookies\n      value: \"1\"\n"
        "    - name: net.core.somaxconn\n      value: \"1024\"\n"
        "  containers:\n  - name: app\n    image: nginx\n",
        encoding="utf-8",
    )
    findings = K8sUnsafeSysctlGuard().run(tmp_path, _k8s_prof(tmp_path))
    rules = {f.rule for f in findings}
    assert rules == {"k8s-unsafe-sysctl/kernel.msgmax", "k8s-unsafe-sysctl/net.core.somaxconn"}


def test_k8s_unsafe_sysctl_passes_documented_safe_sysctls(tmp_path: Path) -> None:
    (tmp_path / "pod.yaml").write_text(
        "apiVersion: v1\nkind: Pod\nmetadata:\n  name: ok\nspec:\n"
        "  securityContext:\n    sysctls:\n"
        "    - name: kernel.shm_rmid_forced\n      value: \"1\"\n"
        "    - name: net.ipv4.tcp_syncookies\n      value: \"1\"\n"
        "    - name: net.ipv4.ip_local_port_range\n      value: \"1024 65535\"\n"
        "  containers:\n  - name: app\n    image: nginx\n",
        encoding="utf-8",
    )
    assert K8sUnsafeSysctlGuard().run(tmp_path, _k8s_prof(tmp_path)) == []


def test_k8s_unsafe_sysctl_passes_pod_with_no_sysctls(tmp_path: Path) -> None:
    (tmp_path / "pod.yaml").write_text(
        "apiVersion: v1\nkind: Pod\nmetadata:\n  name: ok\nspec:\n"
        "  containers:\n  - name: app\n    image: nginx\n",
        encoding="utf-8",
    )
    assert K8sUnsafeSysctlGuard().run(tmp_path, _k8s_prof(tmp_path)) == []


def test_k8s_unsafe_sysctl_passes_out_of_scope_prefixes(tmp_path: Path) -> None:
    # Scope boundary (documented in the guard): the curated unsafe list is `kernel.`/`net.`
    # ONLY. `vm.*` and `fs.*` sysctls are deliberately OUT of scope, so they must NOT fire --
    # a broader guard flagging every non-kernel/net sysctl would be noisy and outside this
    # candidate's stated remit.
    (tmp_path / "pod.yaml").write_text(
        "apiVersion: v1\nkind: Pod\nmetadata:\n  name: ok\nspec:\n"
        "  securityContext:\n    sysctls:\n"
        '    - name: vm.swappiness\n      value: "10"\n'
        '    - name: fs.file-max\n      value: "100000"\n'
        "  containers:\n  - name: app\n    image: nginx\n",
        encoding="utf-8",
    )
    assert K8sUnsafeSysctlGuard().run(tmp_path, _k8s_prof(tmp_path)) == []


def test_k8s_unsafe_sysctl_pragma_opt_out(tmp_path: Path) -> None:
    (tmp_path / "pod.yaml").write_text(
        "apiVersion: v1\nkind: Pod\nmetadata:\n  name: allowed\nspec:\n"
        "  securityContext:\n    sysctls:\n"
        "    - name: kernel.msgmax  # security: allow-k8s-unsafe-sysctl\n      value: \"65536\"\n"
        "  containers:\n  - name: app\n    image: nginx\n",
        encoding="utf-8",
    )
    assert K8sUnsafeSysctlGuard().run(tmp_path, _k8s_prof(tmp_path)) == []


def test_k8s_unsafe_sysctl_not_applicable_without_k8s_feature() -> None:
    prof = mkprofile(Path("/tmp"), features={"docker"})
    assert K8sUnsafeSysctlGuard().applies(prof) is False
