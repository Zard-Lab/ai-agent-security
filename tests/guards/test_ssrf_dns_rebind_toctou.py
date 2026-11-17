"""Tests for SsrfDnsRebindToctouGuard — planted-violation + FP-bait."""
from __future__ import annotations

import pytest

from agentsec.guards.ssrf_dns_rebind_toctou import SsrfDnsRebindToctouGuard
from tests._timing import assert_growth
from tests.guards._common import *  # noqa: F401,F403


def _prof(root: Path) -> StackProfile:
    return mkprofile(root, features={"python"}, python_dirs=["."])


def test_validate_then_fetch_no_ip_pin_fires(tmp_path: Path) -> None:
    (tmp_path / "gateway_fetcher.py").write_text(
        "import requests\n\n"
        "def fetch_via_gateway(url):\n"
        "    if not validate_safe_url(url):\n"
        "        raise ValueError('unsafe url')\n"
        "    response = requests.get(url)\n"
        "    return response.text\n",
        encoding="utf-8",
    )
    findings = SsrfDnsRebindToctouGuard().run(tmp_path, _prof(tmp_path))
    hit = next(f for f in findings if f.rule == "ssrf-dns-rebind-toctou/no-ip-pinning")
    assert hit.severity == "high"


def test_body_recognized_guard_with_unusual_name_fires(tmp_path: Path) -> None:
    """The real CVE-2026-53708 shape: a guard named validate_gateway_test_url (not in the
    closed name list) is still recognized because its BODY resolves + range-checks."""
    (tmp_path / "gateway.py").write_text(
        "import socket, requests\n\n"
        "def validate_gateway_test_url(url):\n"
        "    ip = socket.gethostbyname(url)\n"
        "    return not is_private(ip)\n\n"
        "def test_gateway(url):\n"
        "    if not validate_gateway_test_url(url):\n"
        "        raise ValueError('unsafe')\n"
        "    response = requests.get(url)\n"
        "    return response.text\n",
        encoding="utf-8",
    )
    findings = SsrfDnsRebindToctouGuard().run(tmp_path, _prof(tmp_path))
    assert any(f.rule == "ssrf-dns-rebind-toctou/no-ip-pinning" for f in findings)


def test_ip_pinned_via_http_adapter_is_safe(tmp_path: Path) -> None:
    """FP-bait: the resolved IP is pinned via an HTTPAdapter -- safe."""
    (tmp_path / "gateway_fetcher.py").write_text(
        "import requests\n"
        "from requests.adapters import HTTPAdapter\n\n"
        "def fetch_via_gateway(url):\n"
        "    if not validate_safe_url(url):\n"
        "        raise ValueError('unsafe url')\n"
        "    session = requests.Session()\n"
        "    session.mount('https://', HTTPAdapter())\n"
        "    response = session.get(url)\n"
        "    return response.text\n",
        encoding="utf-8",
    )
    findings = SsrfDnsRebindToctouGuard().run(tmp_path, _prof(tmp_path))
    assert findings == []


def test_no_validator_call_is_safe(tmp_path: Path) -> None:
    """FP-bait: a plain fetch with no preceding guard call at all is out of scope."""
    (tmp_path / "fetcher.py").write_text(
        "import requests\n\n"
        "def fetch(url):\n"
        "    return requests.get(url).text\n",
        encoding="utf-8",
    )
    findings = SsrfDnsRebindToctouGuard().run(tmp_path, _prof(tmp_path))
    assert findings == []


def test_unrelated_function_name_with_no_resolve_body_is_safe(tmp_path: Path) -> None:
    """FP-bait: a function whose name doesn't match the guard vocabulary AND whose body
    doesn't resolve+range-check is never treated as a guard."""
    (tmp_path / "fetcher.py").write_text(
        "import requests\n\n"
        "def prepare_request(url):\n"
        "    return url.strip()\n\n"
        "def fetch(url):\n"
        "    clean = prepare_request(url)\n"
        "    return requests.get(clean).text\n",
        encoding="utf-8",
    )
    findings = SsrfDnsRebindToctouGuard().run(tmp_path, _prof(tmp_path))
    assert findings == []


def test_pragma_suppresses_finding(tmp_path: Path) -> None:
    (tmp_path / "gateway_fetcher.py").write_text(
        "# security: allow-ssrf-dns-rebind-toctou\n"
        "import requests\n\n"
        "def fetch_via_gateway(url):\n"
        "    if not validate_safe_url(url):\n"
        "        raise ValueError('unsafe url')\n"
        "    response = requests.get(url)\n"
        "    return response.text\n",
        encoding="utf-8",
    )
    findings = SsrfDnsRebindToctouGuard().run(tmp_path, _prof(tmp_path))
    assert findings == []


def test_guard_not_applicable_without_python_feature(tmp_path: Path) -> None:
    prof = mkprofile(tmp_path, features={"typescript"}, python_dirs=["."])
    assert SsrfDnsRebindToctouGuard().applies(prof) is False


# --------------------------------------------------------------------------- PR #963 review round
def _run(tmp_path: Path, body: str) -> list[str]:
    (tmp_path / "app.py").write_text(body, encoding="utf-8")
    return [f.rule for f in SsrfDnsRebindToctouGuard().run(tmp_path, _prof(tmp_path))]


_FIRES = ["ssrf-dns-rebind-toctou/no-ip-pinning"]


def test_dict_get_after_validator_is_not_a_fetch(tmp_path: Path) -> None:
    """The review's repro: `config.get("key")` after a validator call is a dict read, not a fetch."""
    assert _run(
        tmp_path,
        "import requests\n\n"
        "def fetch(url, config):\n"
        "    validate_safe_url(url)\n"
        "    timeout = config.get(\"key\")\n"
        "    return timeout\n",
    ) == []


def test_response_header_and_metadata_reads_are_not_fetches(tmp_path: Path) -> None:
    assert _run(
        tmp_path,
        "def read(url, response, result):\n"
        "    validate_safe_url(url)\n"
        "    a = response.headers.get(name_of_header)\n"
        "    return result.metadata.get('title', url)\n",
    ) == []


def test_requests_get_variable_still_fires(tmp_path: Path) -> None:
    assert _run(
        tmp_path,
        "import requests\n\ndef f(url):\n    validate_safe_url(url)\n    return requests.get(url)\n",
    ) == _FIRES


def test_client_shaped_and_bound_receivers_still_fire(tmp_path: Path) -> None:
    assert _run(
        tmp_path,
        "def f(self, url):\n    validate_safe_url(url)\n    return self._client.get(url)\n",
    ) == _FIRES
    assert _run(
        tmp_path,
        "import httpx\n\nasync def f(url):\n    validate_safe_url(url)\n"
        "    async with httpx.AsyncClient() as c:\n        return await c.get(url)\n",
    ) == _FIRES
    assert _run(
        tmp_path,
        "from urllib.request import urlopen\n\ndef f(url):\n    validate_safe_url(url)\n"
        "    return urlopen(url)\n",
    ) == _FIRES


def test_body_scan_stays_linear_in_function_count(tmp_path: Path) -> None:
    """Regression pin for the verified perf fix: `_guard_functions` used to call
    `ast.get_source_segment` per function, which re-splits the whole file each time (O(functions x
    file size), 11.6 s on a 6.8k-line file). Growth ratio, not wall clock (tests/_timing.py)."""

    def scan(n: int) -> None:
        root = tmp_path / str(n)
        root.mkdir(exist_ok=True)
        body = "".join(f"def helper_{i}(x):\n    return x + {i}\n\n" for i in range(n))
        (root / "big.py").write_text(body, encoding="utf-8")
        assert SsrfDnsRebindToctouGuard().run(root, _prof(root)) == []

    assert_growth(scan, [1000, 2000, 4000, 8000], expected="linear")


def test_ssrf_dns_rebind_toctou_pragma_quoted_in_a_string_does_not_suppress(tmp_path: Path) -> None:
    # #424 E6 (#1000): the whole-file opt-out reads the Python comment view, so a docstring quoting
    # the pragma is content. Only a real `#` comment (`test_pragma_suppresses_finding`) opts out.
    assert _run(
        tmp_path,
        '"""Opt out of this check: add # security: allow-ssrf-dns-rebind-toctou."""\n'
        "import requests\n\n"
        "def fetch_via_gateway(url):\n"
        "    if not validate_safe_url(url):\n"
        "        raise ValueError('unsafe url')\n"
        "    response = requests.get(url)\n"
        "    return response.text\n",
    ) == _FIRES


@pytest.mark.parametrize("prefix", _VENDORED_PREFIXES)
def test_vendored_copy_is_never_scanned_but_first_party_still_fires(tmp_path: Path, prefix: str) -> None:
    """#1042: the guard enumerates through the shared walker. With a bare `rglob` it read and parsed
    every site-packages file under the scan dir (273s on 50k files, killed over its 60s budget) and
    reported the canary inside `.venv` as a HIGH finding. The same code in first-party source must
    still fire, so the walker change narrows only the vendored tree."""
    plant = SsrfDnsRebindToctouGuard.canary_plant
    assert plant is not None
    canary = plant.files["gateway_fetcher.py"]
    _plant(tmp_path, f"{prefix}/gateway_fetcher.py", canary)
    _plant(tmp_path, "app/gateway_fetcher.py", canary)
    findings = SsrfDnsRebindToctouGuard().run(tmp_path, _prof(tmp_path))
    assert {f.location.replace("\\", "/").rsplit(":", 1)[0] for f in findings} == {"app/gateway_fetcher.py"}


def test_gitignored_python_file_is_not_scanned_but_a_tracked_neighbour_still_fires(tmp_path: Path) -> None:
    """#1044 review M1: through the shared walker this guard honours `.gitignore`, like every sibling
    Python guard (the old `rglob` did not). Pinned in both directions: the ignored file is silent, a
    tracked file with the same code in the same dir still fires."""
    plant = SsrfDnsRebindToctouGuard.canary_plant
    assert plant is not None
    canary = plant.files["gateway_fetcher.py"]
    _plant(tmp_path, ".gitignore", "app/scratch_fetcher.py\n")
    _plant(tmp_path, "app/scratch_fetcher.py", canary)
    _plant(tmp_path, "app/gateway_fetcher.py", canary)
    findings = SsrfDnsRebindToctouGuard().run(tmp_path, _prof(tmp_path))
    assert {f.location.replace("\\", "/").rsplit(":", 1)[0] for f in findings} == {"app/gateway_fetcher.py"}
