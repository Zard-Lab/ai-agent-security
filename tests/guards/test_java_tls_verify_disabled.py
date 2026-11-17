from __future__ import annotations

from agentsec.guards.java_tls_verify_disabled import JavaTlsVerifyDisabledGuard
from tests.guards._common import *  # noqa: F401,F403


def test_java_tls_verify_disabled_flags_empty_check_server_trusted(tmp_path: Path) -> None:
    (tmp_path / "T.java").write_text(
        "import javax.net.ssl.X509TrustManager;\n"
        "import java.security.cert.X509Certificate;\n"
        "class T {\n"
        "    X509TrustManager tm = new X509TrustManager() {\n"
        "        public void checkClientTrusted(X509Certificate[] chain, String authType) {\n"
        "        }\n"
        "        public void checkServerTrusted(X509Certificate[] chain, String authType) {\n"
        "        }\n"
        "        public X509Certificate[] getAcceptedIssuers() { return null; }\n"
        "    };\n"
        "}\n",
        encoding="utf-8",
    )
    findings = JavaTlsVerifyDisabledGuard().run(tmp_path, _javaprof(tmp_path))
    # Both checkClientTrusted and checkServerTrusted are empty here — two findings, same rule.
    assert len(findings) == 2
    assert all(f.rule == "java-tls-verify-disabled/empty-trust-manager" for f in findings)
    assert all(f.severity == "high" for f in findings)


def test_java_tls_verify_disabled_flags_only_check_client_trusted_empty(tmp_path: Path) -> None:
    (tmp_path / "T.java").write_text(
        "import javax.net.ssl.X509TrustManager;\n"
        "import java.security.cert.X509Certificate;\n"
        "class T {\n"
        "    X509TrustManager tm = new X509TrustManager() {\n"
        "        public void checkClientTrusted(X509Certificate[] chain, String authType) {\n"
        "        }\n"
        "        public void checkServerTrusted(X509Certificate[] chain, String authType)\n"
        "                throws java.security.cert.CertificateException {\n"
        "            chain[0].checkValidity();\n"
        "        }\n"
        "        public X509Certificate[] getAcceptedIssuers() { return null; }\n"
        "    };\n"
        "}\n",
        encoding="utf-8",
    )
    findings = JavaTlsVerifyDisabledGuard().run(tmp_path, _javaprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "java-tls-verify-disabled/empty-trust-manager"


def test_java_tls_verify_disabled_silent_on_real_validation(tmp_path: Path) -> None:
    # FP-bait: a body that actually validates and throws must not fire.
    (tmp_path / "T.java").write_text(
        "import javax.net.ssl.X509TrustManager;\n"
        "import java.security.cert.X509Certificate;\n"
        "class T {\n"
        "    X509TrustManager tm = new X509TrustManager() {\n"
        "        public void checkServerTrusted(X509Certificate[] chain, String authType)\n"
        "                throws java.security.cert.CertificateException {\n"
        "            if (chain == null || chain.length == 0) {\n"
        '                throw new java.security.cert.CertificateException("empty chain");\n'
        "            }\n"
        "            chain[0].checkValidity();\n"
        "        }\n"
        "        public void checkClientTrusted(X509Certificate[] chain, String authType)\n"
        "                throws java.security.cert.CertificateException {\n"
        "            chain[0].checkValidity();\n"
        "        }\n"
        "        public X509Certificate[] getAcceptedIssuers() { return null; }\n"
        "    };\n"
        "}\n",
        encoding="utf-8",
    )
    assert JavaTlsVerifyDisabledGuard().run(tmp_path, _javaprof(tmp_path)) == []


def test_java_tls_verify_disabled_silent_when_delegating_to_default(tmp_path: Path) -> None:
    # FP-bait: delegating to a real (default) TrustManager's own check* call must not fire —
    # and must not be confused with a call SITE being mistaken for a definition either.
    (tmp_path / "T.java").write_text(
        "import javax.net.ssl.X509TrustManager;\n"
        "import java.security.cert.X509Certificate;\n"
        "class T {\n"
        "    X509TrustManager defaultTrustManager;\n"
        "    X509TrustManager tm = new X509TrustManager() {\n"
        "        public void checkServerTrusted(X509Certificate[] chain, String authType)\n"
        "                throws java.security.cert.CertificateException {\n"
        "            defaultTrustManager.checkServerTrusted(chain, authType);\n"
        "        }\n"
        "        public void checkClientTrusted(X509Certificate[] chain, String authType)\n"
        "                throws java.security.cert.CertificateException {\n"
        "            defaultTrustManager.checkClientTrusted(chain, authType);\n"
        "        }\n"
        "        public X509Certificate[] getAcceptedIssuers() { return null; }\n"
        "    };\n"
        "}\n",
        encoding="utf-8",
    )
    assert JavaTlsVerifyDisabledGuard().run(tmp_path, _javaprof(tmp_path)) == []


def test_java_tls_verify_disabled_silent_on_abstract_declaration(tmp_path: Path) -> None:
    # FP-bait: an interface's abstract method declaration (ends in ";", no body at all) must
    # not fire.
    (tmp_path / "T.java").write_text(
        "interface MyTrustManager {\n"
        "    void checkServerTrusted(Object[] chain, String authType) throws Exception;\n"
        "}\n",
        encoding="utf-8",
    )
    assert JavaTlsVerifyDisabledGuard().run(tmp_path, _javaprof(tmp_path)) == []


def test_java_tls_verify_disabled_silent_in_line_comment(tmp_path: Path) -> None:
    # FP-bait: a `//` comment mentioning the pattern must not fire.
    (tmp_path / "T.java").write_text(
        "class T {\n"
        "    // an example: public void checkServerTrusted(X509Certificate[] chain, String authType) { }\n"
        "    void real() { int x = 1; }\n"
        "}\n",
        encoding="utf-8",
    )
    assert JavaTlsVerifyDisabledGuard().run(tmp_path, _javaprof(tmp_path)) == []


def test_java_tls_verify_disabled_silent_in_javadoc(tmp_path: Path) -> None:
    # FP-bait: a Javadoc block comment mentioning the pattern must not fire.
    (tmp_path / "T.java").write_text(
        "/**\n"
        " * Do not implement checkServerTrusted(chain, authType) as a no-op.\n"
        " */\n"
        "class T {\n"
        "    void real() { int x = 1; }\n"
        "}\n",
        encoding="utf-8",
    )
    assert JavaTlsVerifyDisabledGuard().run(tmp_path, _javaprof(tmp_path)) == []


def test_java_tls_verify_disabled_pragma_silences(tmp_path: Path) -> None:
    (tmp_path / "T.java").write_text(
        "import javax.net.ssl.X509TrustManager;\n"
        "import java.security.cert.X509Certificate;\n"
        "class T {\n"
        "    X509TrustManager tm = new X509TrustManager() {\n"
        "        public void checkServerTrusted(X509Certificate[] chain, String authType) { }"
        " // security: allow-java-tls-verify-disabled\n"
        "        public X509Certificate[] getAcceptedIssuers() { return null; }\n"
        "    };\n"
        "}\n",
        encoding="utf-8",
    )
    assert JavaTlsVerifyDisabledGuard().run(tmp_path, _javaprof(tmp_path)) == []


def test_java_tls_verify_disabled_not_applicable_without_java() -> None:
    prof = mkprofile(Path("/tmp"), features={"python"})
    assert JavaTlsVerifyDisabledGuard().applies(prof) is False


def test_java_tls_verify_disabled_skips_maven_test_tree(tmp_path: Path) -> None:
    # Narrowing gate (PR #839 review): Maven/Gradle put test sources under `src/test/java`, whose
    # `test` segment `is_nonproduct_path` reads as non-product. Both trees carry the SAME violation
    # in one run, so this pins the skip AND the direction traded against it — production code under
    # `src/main/java` must still fire.
    src = (
        "import javax.net.ssl.X509TrustManager;\n"
        "import java.security.cert.X509Certificate;\n"
        "class T {\n"
        "    X509TrustManager tm = new X509TrustManager() {\n"
        "        public void checkServerTrusted(X509Certificate[] chain, String authType) {\n"
        "        }\n"
        "        public X509Certificate[] getAcceptedIssuers() { return null; }\n"
        "    };\n"
        "}\n"
    )
    for tree in ("main", "test"):
        d = tmp_path / "src" / tree / "java"
        d.mkdir(parents=True)
        (d / "T.java").write_text(src, encoding="utf-8")
    findings = JavaTlsVerifyDisabledGuard().run(tmp_path, _javaprof(tmp_path))
    assert findings
    assert {f.location.split(":")[0].replace("\\", "/") for f in findings} == {"src/main/java/T.java"}
