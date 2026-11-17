from __future__ import annotations

from agentsec.guards.arm_apim_backend_unauthenticated import ArmApimBackendUnauthenticatedGuard
from tests.guards._common import *  # noqa: F401,F403


def _armprof(tmp_path: Path) -> StackProfile:
    return mkprofile(tmp_path, features={"arm"})


def test_arm_apim_backend_flags_http_no_credentials(tmp_path: Path) -> None:
    (tmp_path / "template.json").write_text(
        '{"resources": [{"type": "Microsoft.ApiManagement/service/backends", '
        '"name": "myApim/myBackend", "properties": {'
        '"url": "http://internal-service.example.com/api", "protocol": "http"}}]}',
        encoding="utf-8",
    )
    findings = ArmApimBackendUnauthenticatedGuard().run(tmp_path, _armprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "arm-apim-backend-unauthenticated/http-no-auth"
    assert findings[0].severity == "high"


def test_arm_apim_backend_silent_when_credentials_present(tmp_path: Path) -> None:
    (tmp_path / "template.json").write_text(
        '{"resources": [{"type": "Microsoft.ApiManagement/service/backends", '
        '"name": "myApim/myBackend", "properties": {'
        '"url": "http://internal-service.example.com/api", "protocol": "http", '
        '"credentials": {"authorization": {"scheme": "Basic", "parameter": "abc"}}}}]}',
        encoding="utf-8",
    )
    assert ArmApimBackendUnauthenticatedGuard().run(tmp_path, _armprof(tmp_path)) == []


def test_arm_apim_backend_silent_on_https_url(tmp_path: Path) -> None:
    (tmp_path / "template.json").write_text(
        '{"resources": [{"type": "Microsoft.ApiManagement/service/backends", '
        '"name": "myApim/myBackend", "properties": {'
        '"url": "https://internal-service.example.com/api", "protocol": "http"}}]}',
        encoding="utf-8",
    )
    assert ArmApimBackendUnauthenticatedGuard().run(tmp_path, _armprof(tmp_path)) == []


def test_arm_apim_backend_silent_when_service_fabric_cluster_present(tmp_path: Path) -> None:
    (tmp_path / "template.json").write_text(
        '{"resources": [{"type": "Microsoft.ApiManagement/service/backends", '
        '"name": "myApim/myBackend", "properties": {'
        '"url": "http://internal-service.example.com/api", "protocol": "http", '
        '"properties": {"serviceFabricCluster": {"clientCertificateId": "abc"}}}}]}',
        encoding="utf-8",
    )
    assert ArmApimBackendUnauthenticatedGuard().run(tmp_path, _armprof(tmp_path)) == []


def test_arm_apim_backend_silent_on_unrelated_resource_type(tmp_path: Path) -> None:
    # FP-bait: a different resource type entirely, even one carrying similarly-named properties.
    (tmp_path / "template.json").write_text(
        '{"resources": [{"type": "Microsoft.ApiManagement/service/apis", '
        '"name": "myApim/myApi", "properties": {'
        '"url": "http://internal-service.example.com/api", "protocol": "http"}}]}',
        encoding="utf-8",
    )
    assert ArmApimBackendUnauthenticatedGuard().run(tmp_path, _armprof(tmp_path)) == []


def test_arm_apim_backend_fires_when_protocol_absent_and_url_is_http(tmp_path: Path) -> None:
    # No "protocol" key at all -- judge by the URL scheme alone (ambiguous-protocol posture).
    (tmp_path / "template.json").write_text(
        '{"resources": [{"type": "Microsoft.ApiManagement/service/backends", '
        '"name": "myApim/myBackend", "properties": {'
        '"url": "http://internal-service.example.com/api"}}]}',
        encoding="utf-8",
    )
    findings = ArmApimBackendUnauthenticatedGuard().run(tmp_path, _armprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "arm-apim-backend-unauthenticated/http-no-auth"


def test_arm_apim_backend_silent_when_protocol_present_but_not_http(tmp_path: Path) -> None:
    # protocol explicitly says something other than "http" (e.g. "https") while the URL string
    # happens to start with http:// -- an inconsistent template this guard doesn't adjudicate.
    (tmp_path / "template.json").write_text(
        '{"resources": [{"type": "Microsoft.ApiManagement/service/backends", '
        '"name": "myApim/myBackend", "properties": {'
        '"url": "http://internal-service.example.com/api", "protocol": "https"}}]}',
        encoding="utf-8",
    )
    assert ArmApimBackendUnauthenticatedGuard().run(tmp_path, _armprof(tmp_path)) == []


def test_arm_apim_backend_silent_when_url_absent(tmp_path: Path) -> None:
    (tmp_path / "template.json").write_text(
        '{"resources": [{"type": "Microsoft.ApiManagement/service/backends", '
        '"name": "myApim/myBackend", "properties": {"protocol": "http"}}]}',
        encoding="utf-8",
    )
    assert ArmApimBackendUnauthenticatedGuard().run(tmp_path, _armprof(tmp_path)) == []


_NESTED_APIM = """{
  "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
  "resources": [
    {
      "type": "Microsoft.ApiManagement/service",
      "name": "prodapim",
      "resources": [
        {
          "type": "backends",
          "name": "legacy",
          "properties": {"url": "http://internal-service.example.com/api", "protocol": "http"%s}
        }
      ]
    }
  ]
}
"""


def test_arm_apim_backend_flags_inline_nested_child_authoring_style(tmp_path: Path) -> None:
    # Same violation as the flat fully-qualified form, authored as an inline child with a
    # relative type. Both deploy identically, so both must fire.
    (tmp_path / "template.json").write_text(_NESTED_APIM % "", encoding="utf-8")
    findings = ArmApimBackendUnauthenticatedGuard().run(tmp_path, _armprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "arm-apim-backend-unauthenticated/http-no-auth"
    assert findings[0].severity == "high"
    # The message names the resolved full resource name, not the bare child segment.
    assert "prodapim/legacy" in findings[0].message


def test_arm_apim_backend_silent_on_nested_child_with_credentials(tmp_path: Path) -> None:
    # FP-bait for the nested form: credentials present means authentication is configured.
    (tmp_path / "template.json").write_text(
        _NESTED_APIM % ', "credentials": {"header": {"x-api-key": ["[parameters(\'k\')]"]}}',
        encoding="utf-8",
    )
    assert ArmApimBackendUnauthenticatedGuard().run(tmp_path, _armprof(tmp_path)) == []


def test_arm_apim_backend_not_applicable_without_arm() -> None:
    prof = mkprofile(Path("/tmp"), features={"terraform"})
    assert ArmApimBackendUnauthenticatedGuard().applies(prof) is False
