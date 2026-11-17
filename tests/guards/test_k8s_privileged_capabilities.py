from __future__ import annotations

from agentsec.guards.k8s_privileged_capabilities import K8sPrivilegedCapabilitiesGuard
from tests.guards._common import *  # noqa: F401,F403


def _k8s_prof(root: Path) -> StackProfile:
    return mkprofile(root, features={"k8s"})


def test_k8s_privileged_capabilities_fires_sys_admin(tmp_path: Path) -> None:
    (tmp_path / "pod.yaml").write_text(
        "apiVersion: v1\nkind: Pod\nmetadata:\n  name: bad\nspec:\n"
        "  containers:\n  - name: app\n    image: nginx\n    securityContext:\n"
        "      capabilities:\n        add:\n        - SYS_ADMIN\n",
        encoding="utf-8",
    )
    findings = K8sPrivilegedCapabilitiesGuard().run(tmp_path, _k8s_prof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "k8s-privileged-capabilities/sys-admin-added"
    assert findings[0].severity == "critical"


def test_k8s_privileged_capabilities_fires_all(tmp_path: Path) -> None:
    (tmp_path / "pod.yaml").write_text(
        "apiVersion: v1\nkind: Pod\nmetadata:\n  name: bad\nspec:\n"
        "  containers:\n  - name: app\n    image: nginx\n    securityContext:\n"
        '      capabilities:\n        add: ["ALL"]\n',
        encoding="utf-8",
    )
    findings = K8sPrivilegedCapabilitiesGuard().run(tmp_path, _k8s_prof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "k8s-privileged-capabilities/all-capabilities-added"


def test_k8s_privileged_capabilities_fires_inline_sys_admin(tmp_path: Path) -> None:
    # the inline-list branch must still fire on an exact dangerous cap
    (tmp_path / "pod.yaml").write_text(
        "apiVersion: v1\nkind: Pod\nmetadata:\n  name: bad\nspec:\n"
        "  containers:\n  - name: app\n    image: nginx\n    securityContext:\n"
        '      capabilities:\n        add: ["SYS_ADMIN"]\n',
        encoding="utf-8",
    )
    findings = K8sPrivilegedCapabilitiesGuard().run(tmp_path, _k8s_prof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "k8s-privileged-capabilities/sys-admin-added"


def test_k8s_privileged_capabilities_fires_inline_multi_token(tmp_path: Path) -> None:
    # both dangerous caps in one inline list must be detected (comma-split whole-match)
    (tmp_path / "pod.yaml").write_text(
        "apiVersion: v1\nkind: Pod\nmetadata:\n  name: bad\nspec:\n"
        "  containers:\n  - name: app\n    image: nginx\n    securityContext:\n"
        "      capabilities:\n        add: [SYS_ADMIN, ALL]\n",
        encoding="utf-8",
    )
    rules = {f.rule for f in K8sPrivilegedCapabilitiesGuard().run(tmp_path, _k8s_prof(tmp_path))}
    assert rules == {
        "k8s-privileged-capabilities/sys-admin-added",
        "k8s-privileged-capabilities/all-capabilities-added",
    }


def test_k8s_privileged_capabilities_no_fp_on_cap_name_containing_all(tmp_path: Path) -> None:
    # #402 Major-2: a benign capability whose NAME merely contains a dangerous keyword —
    # `metrics-wALLboard` (contains ALL) or `install-all` (a hyphen-segment ALL) — must NOT fire the
    # CRITICAL `ALL` case. Whole-entry match, not substring/token containment.
    for cap in ("metrics-wallboard", "install-all"):
        (tmp_path / "pod.yaml").write_text(
            "apiVersion: v1\nkind: Pod\nmetadata:\n  name: ok\nspec:\n"
            "  containers:\n  - name: app\n    image: nginx\n    securityContext:\n"
            f'      capabilities:\n        add: ["{cap}"]\n',
            encoding="utf-8",
        )
        assert K8sPrivilegedCapabilitiesGuard().run(tmp_path, _k8s_prof(tmp_path)) == [], cap


def test_k8s_privileged_capabilities_fires_with_comment_inside_add_block(tmp_path: Path) -> None:
    # Regression (#422 S10): a comment (or blank) line between `add:` and the list item must
    # not end the block scan; the seccomp sibling already skips such lines.
    (tmp_path / "pod.yaml").write_text(
        "apiVersion: v1\nkind: Pod\nmetadata:\n  name: bad\nspec:\n"
        "  containers:\n  - name: app\n    image: nginx\n    securityContext:\n"
        "      capabilities:\n        add:\n"
        "        # elevated for device mounts\n"
        "\n"
        "        - SYS_ADMIN\n",
        encoding="utf-8",
    )
    findings = K8sPrivilegedCapabilitiesGuard().run(tmp_path, _k8s_prof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "k8s-privileged-capabilities/sys-admin-added"


def test_k8s_privileged_capabilities_add_block_still_ends_at_next_key(tmp_path: Path) -> None:
    # FP-bait for the widened block scan: the `add:` block ends at the next real key, so a
    # `- SYS_ADMIN` under a later `drop:` list (removing the cap is the FIX) must not fire.
    (tmp_path / "pod.yaml").write_text(
        "apiVersion: v1\nkind: Pod\nmetadata:\n  name: ok\nspec:\n"
        "  containers:\n  - name: app\n    image: nginx\n    securityContext:\n"
        "      capabilities:\n        add:\n"
        "        - NET_BIND_SERVICE\n"
        "        drop:\n"
        "        - SYS_ADMIN\n"
        "        - ALL\n",
        encoding="utf-8",
    )
    assert K8sPrivilegedCapabilitiesGuard().run(tmp_path, _k8s_prof(tmp_path)) == []


def test_k8s_privileged_capabilities_passes_narrow_capability(tmp_path: Path) -> None:
    # NET_BIND_SERVICE + a drop:ALL baseline is the recommended shape -- must stay silent
    # (this guard deliberately only flags the ADD side, not a missing drop:ALL -- see module doc).
    (tmp_path / "pod.yaml").write_text(
        "apiVersion: v1\nkind: Pod\nmetadata:\n  name: ok\nspec:\n"
        "  containers:\n  - name: app\n    image: nginx\n    securityContext:\n"
        "      capabilities:\n        add:\n        - NET_BIND_SERVICE\n        drop:\n        - ALL\n",
        encoding="utf-8",
    )
    assert K8sPrivilegedCapabilitiesGuard().run(tmp_path, _k8s_prof(tmp_path)) == []


def test_k8s_privileged_capabilities_passes_no_capabilities_block(tmp_path: Path) -> None:
    (tmp_path / "pod.yaml").write_text(
        "apiVersion: v1\nkind: Pod\nmetadata:\n  name: ok\nspec:\n"
        "  containers:\n  - name: app\n    image: nginx\n",
        encoding="utf-8",
    )
    assert K8sPrivilegedCapabilitiesGuard().run(tmp_path, _k8s_prof(tmp_path)) == []


def test_k8s_privileged_capabilities_pragma_opt_out(tmp_path: Path) -> None:
    (tmp_path / "pod.yaml").write_text(
        "apiVersion: v1\nkind: Pod\nmetadata:\n  name: allowed\nspec:\n"
        "  containers:\n  - name: app\n    image: nginx\n    securityContext:\n"
        "      capabilities:\n        add:\n        - SYS_ADMIN\n"
        "      # security: allow-k8s-privileged-capabilities\n",
        encoding="utf-8",
    )
    assert K8sPrivilegedCapabilitiesGuard().run(tmp_path, _k8s_prof(tmp_path)) == []


def test_k8s_privileged_capabilities_not_applicable_without_k8s_feature() -> None:
    prof = mkprofile(Path("/tmp"), features={"docker"})
    assert K8sPrivilegedCapabilitiesGuard().applies(prof) is False
