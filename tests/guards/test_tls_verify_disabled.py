from __future__ import annotations

from agentsec.guards.tls_verify_disabled import TlsVerifyDisabledGuard
from tests.guards._common import *  # noqa: F401,F403


def test_tls_verify_disabled_fires_on_requests_get(tmp_path: Path) -> None:
    (tmp_path / "client.py").write_text(
        "resp = requests.get(url, verify=False)\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python"})
    findings = TlsVerifyDisabledGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "tls-verify-disabled/verify-false"
    assert findings[0].severity == "high"


def test_tls_verify_disabled_fires_on_httpx_client_ctor(tmp_path: Path) -> None:
    (tmp_path / "client.py").write_text(
        "client = httpx.Client(verify=False, timeout=30)\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python"})
    findings = TlsVerifyDisabledGuard().run(tmp_path, profile)
    assert len(findings) == 1


def test_tls_verify_disabled_fires_on_session_attr_assign(tmp_path: Path) -> None:
    (tmp_path / "client.py").write_text(
        "session = requests.Session()\n"
        "session.verify = False\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python"})
    findings = TlsVerifyDisabledGuard().run(tmp_path, profile)
    assert len(findings) == 1


def test_tls_verify_disabled_silent_on_verify_true(tmp_path: Path) -> None:
    (tmp_path / "client.py").write_text(
        "resp = requests.get(url, verify=True)\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python"})
    assert TlsVerifyDisabledGuard().run(tmp_path, profile) == []


def test_tls_verify_disabled_silent_on_ca_bundle_path(tmp_path: Path) -> None:
    # FP-bait: verify pointed at a real CA bundle path is the correct pattern.
    (tmp_path / "client.py").write_text(
        'resp = requests.get(url, verify="/etc/ssl/internal-ca.pem")\n',
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python"})
    assert TlsVerifyDisabledGuard().run(tmp_path, profile) == []


def test_tls_verify_disabled_silent_on_unrelated_verify_false(tmp_path: Path) -> None:
    # FP-bait: `verify=False` for an unrelated function (not requests/httpx) must not fire.
    (tmp_path / "misc.py").write_text(
        "result = some_validator(data, verify=False)\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python"})
    assert TlsVerifyDisabledGuard().run(tmp_path, profile) == []


def test_tls_verify_disabled_silent_on_unrelated_attr_assign(tmp_path: Path) -> None:
    # FP-bait (#305 review): `<obj>.verify = False` on a non-HTTP object, in a file that never
    # touches requests/httpx, must not fire — `.verify` is an overloaded attribute name.
    (tmp_path / "validator.py").write_text(
        "validator = FieldValidator(schema)\n"
        "validator.verify = False  # disable schema checks, not TLS\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python"})
    assert TlsVerifyDisabledGuard().run(tmp_path, profile) == []


def test_tls_verify_disabled_silent_on_self_verify_in_http_file(tmp_path: Path) -> None:
    # Even in a requests-using module, a class setting its OWN `self.verify` flag is not a
    # session and must not fire (sessions are local vars).
    (tmp_path / "svc.py").write_text(
        "import requests\n"
        "class Client:\n"
        "    def __init__(self):\n"
        "        self.verify = False\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python"})
    assert TlsVerifyDisabledGuard().run(tmp_path, profile) == []


def test_tls_verify_disabled_pragma_silences(tmp_path: Path) -> None:
    (tmp_path / "client.py").write_text(
        "# security: allow-tls-verify-disabled\n"
        "resp = requests.get(url, verify=False)\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python"})
    assert TlsVerifyDisabledGuard().run(tmp_path, profile) == []


def test_tls_verify_disabled_not_applies_without_python(tmp_path: Path) -> None:
    profile = mkprofile(tmp_path, features={"frontend"})
    assert TlsVerifyDisabledGuard().applies(profile) is False


def test_tls_verify_disabled_fires_on_ssl_unverified_context(tmp_path: Path) -> None:
    (tmp_path / "client.py").write_text(
        "import ssl\n"
        "ctx = ssl._create_unverified_context()\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python"})
    findings = TlsVerifyDisabledGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "tls-verify-disabled/ssl-unverified-context"


def test_tls_verify_disabled_fires_on_check_hostname_false(tmp_path: Path) -> None:
    (tmp_path / "client.py").write_text(
        "import ssl\n"
        "ctx = ssl.create_default_context()\n"
        "ctx.check_hostname = False\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python"})
    findings = TlsVerifyDisabledGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "tls-verify-disabled/check-hostname-false"


def test_tls_verify_disabled_fires_on_cert_none_sslcontext(tmp_path: Path) -> None:
    (tmp_path / "client.py").write_text(
        "import ssl\n"
        "ctx = ssl.create_default_context()\n"
        "ctx.verify_mode = ssl.CERT_NONE\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python"})
    findings = TlsVerifyDisabledGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "tls-verify-disabled/cert-none"


def test_tls_verify_disabled_fires_on_cert_none_urllib3(tmp_path: Path) -> None:
    (tmp_path / "client.py").write_text(
        "import urllib3\n"
        "http = urllib3.PoolManager(cert_reqs=\"CERT_NONE\")\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python"})
    findings = TlsVerifyDisabledGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "tls-verify-disabled/cert-none"


def test_tls_verify_disabled_fires_on_aiohttp_ssl_false(tmp_path: Path) -> None:
    (tmp_path / "client.py").write_text(
        "import aiohttp\n"
        "connector = aiohttp.TCPConnector(ssl=False)\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python"})
    findings = TlsVerifyDisabledGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "tls-verify-disabled/aiohttp-ssl-false"


def test_tls_verify_disabled_silent_on_aiohttp_ssl_false_without_aiohttp_cue(tmp_path: Path) -> None:
    # FP-bait: ssl=False is a plausible kwarg name in unrelated code — only trusted
    # in files that actually import aiohttp.
    (tmp_path / "misc.py").write_text(
        "result = configure_feature(ssl=False)\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python"})
    assert TlsVerifyDisabledGuard().run(tmp_path, profile) == []


def test_tls_verify_disabled_silent_on_cert_reqs_required(tmp_path: Path) -> None:
    (tmp_path / "client.py").write_text(
        "import urllib3\n"
        "http = urllib3.PoolManager(cert_reqs=\"CERT_REQUIRED\")\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python"})
    assert TlsVerifyDisabledGuard().run(tmp_path, profile) == []


# --- Express/JS (codeql js/disabling-certificate-validation) ---

def test_tls_verify_disabled_applies_on_express() -> None:
    assert TlsVerifyDisabledGuard().applies(mkprofile(Path("/tmp"), features={"express"})) is True


def test_tls_verify_disabled_js_reject_unauthorized_fires(tmp_path: Path) -> None:
    (tmp_path / "client.js").write_text(
        "const https = require('https');\n"
        "https.request(url, { rejectUnauthorized: false }, callback);\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"express"})
    findings = TlsVerifyDisabledGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "tls-verify-disabled/reject-unauthorized-false"
    assert findings[0].severity == "high"


def test_tls_verify_disabled_js_node_tls_env_fires(tmp_path: Path) -> None:
    (tmp_path / "server.js").write_text(
        "process.env.NODE_TLS_REJECT_UNAUTHORIZED = \"0\";\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"express"})
    findings = TlsVerifyDisabledGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "tls-verify-disabled/reject-unauthorized-false"


def test_tls_verify_disabled_js_silent_on_reject_unauthorized_true(tmp_path: Path) -> None:
    (tmp_path / "client.js").write_text(
        "const https = require('https');\n"
        "https.request(url, { rejectUnauthorized: true }, callback);\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"express"})
    assert TlsVerifyDisabledGuard().run(tmp_path, profile) == []


def test_tls_verify_disabled_js_pragma_silences(tmp_path: Path) -> None:
    (tmp_path / "client.js").write_text(
        "https.request(url, { rejectUnauthorized: false }, callback);"
        "  // security: allow-tls-verify-disabled\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"express"})
    assert TlsVerifyDisabledGuard().run(tmp_path, profile) == []
