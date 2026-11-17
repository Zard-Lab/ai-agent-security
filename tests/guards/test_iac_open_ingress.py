from __future__ import annotations

from agentsec.guards.iac_open_ingress import IacOpenIngressGuard
from tests.guards._common import *  # noqa: F401,F403


def test_iac_open_ingress_flags_world_open(tmp_path: Path) -> None:
    (tmp_path / "sg.tf").write_text(_INGRESS_OPEN, encoding="utf-8")
    findings = IacOpenIngressGuard().run(tmp_path, _tf_prof(tmp_path))
    # only the ingress 0.0.0.0/0 fires; the egress one is silent
    assert len(findings) == 1
    assert findings[0].rule == "iac-open-ingress/world-open-ingress"
    assert findings[0].severity == "high"

def test_iac_open_ingress_flags_ipv6_world_open(tmp_path: Path) -> None:
    (tmp_path / "sg.tf").write_text(
        'resource "x" "y" {\n  ingress {\n    ipv6_cidr_blocks = ["::/0"]\n  }\n}\n', encoding="utf-8"
    )
    assert len(IacOpenIngressGuard().run(tmp_path, _tf_prof(tmp_path))) == 1

def test_iac_open_ingress_passes_restricted_cidr(tmp_path: Path) -> None:
    (tmp_path / "sg.tf").write_text(
        'resource "x" "y" {\n  ingress {\n    cidr_blocks = ["10.0.0.0/8"]\n  }\n}\n', encoding="utf-8"
    )
    assert IacOpenIngressGuard().run(tmp_path, _tf_prof(tmp_path)) == []

def test_iac_open_ingress_passes_egress_only(tmp_path: Path) -> None:
    (tmp_path / "sg.tf").write_text(
        'resource "x" "y" {\n  egress {\n    cidr_blocks = ["0.0.0.0/0"]\n  }\n}\n', encoding="utf-8"
    )
    assert IacOpenIngressGuard().run(tmp_path, _tf_prof(tmp_path)) == []

def test_iac_open_ingress_pragma_opt_out(tmp_path: Path) -> None:
    (tmp_path / "sg.tf").write_text(
        'resource "x" "y" {\n  ingress {\n'
        '    cidr_blocks = ["0.0.0.0/0"]  # security: allow-open-ingress\n  }\n}\n', encoding="utf-8"
    )
    assert IacOpenIngressGuard().run(tmp_path, _tf_prof(tmp_path)) == []

def test_iac_open_ingress_na_without_terraform() -> None:
    assert IacOpenIngressGuard().applies(mkprofile(Path("/tmp"), features={"docker"})) is False

