from __future__ import annotations

from agentsec.guards.java_weak_crypto import JavaWeakCryptoGuard
from tests.guards._common import *  # noqa: F401,F403


def test_java_weak_crypto_flags_message_digest_md5(tmp_path: Path) -> None:
    (tmp_path / "T.java").write_text(
        'class T { void m() { MessageDigest.getInstance("MD5"); } }\n', encoding="utf-8"
    )
    findings = JavaWeakCryptoGuard().run(tmp_path, _javaprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "java-weak-crypto/insecure-hash"
    assert findings[0].severity == "high"


def test_java_weak_crypto_flags_message_digest_sha1_both_spellings(tmp_path: Path) -> None:
    (tmp_path / "T.java").write_text(
        'class T { void m() {\n'
        '  MessageDigest.getInstance("SHA1");\n'
        '  MessageDigest.getInstance("SHA-1");\n'
        "} }\n",
        encoding="utf-8",
    )
    findings = JavaWeakCryptoGuard().run(tmp_path, _javaprof(tmp_path))
    assert len(findings) == 2


def test_java_weak_crypto_flags_bare_sha(tmp_path: Path) -> None:
    (tmp_path / "T.java").write_text(
        'class T { void m() { MessageDigest.getInstance("SHA"); } }\n', encoding="utf-8"
    )
    findings = JavaWeakCryptoGuard().run(tmp_path, _javaprof(tmp_path))
    assert len(findings) == 1


def test_java_weak_crypto_flags_digest_utils(tmp_path: Path) -> None:
    (tmp_path / "T.java").write_text(
        "class T { void m() { DigestUtils.md5Hex(data); } }\n", encoding="utf-8"
    )
    findings = JavaWeakCryptoGuard().run(tmp_path, _javaprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "java-weak-crypto/insecure-hash"


def test_java_weak_crypto_flags_bare_aes_cipher(tmp_path: Path) -> None:
    (tmp_path / "T.java").write_text(
        'class T { void m() { Cipher c = Cipher.getInstance("AES"); } }\n', encoding="utf-8"
    )
    findings = JavaWeakCryptoGuard().run(tmp_path, _javaprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "java-weak-crypto/weak-cipher-mode"


def test_java_weak_crypto_flags_explicit_ecb_mode(tmp_path: Path) -> None:
    (tmp_path / "T.java").write_text(
        'class T { void m() { Cipher.getInstance("AES/ECB/PKCS5Padding"); } }\n', encoding="utf-8"
    )
    findings = JavaWeakCryptoGuard().run(tmp_path, _javaprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "java-weak-crypto/weak-cipher-mode"


def test_java_weak_crypto_silent_on_sha256(tmp_path: Path) -> None:
    # FP-bait: a modern, non-broken digest must not fire.
    (tmp_path / "T.java").write_text(
        'class T { void m() { MessageDigest.getInstance("SHA-256"); } }\n', encoding="utf-8"
    )
    assert JavaWeakCryptoGuard().run(tmp_path, _javaprof(tmp_path)) == []


def test_java_weak_crypto_silent_on_gcm_mode(tmp_path: Path) -> None:
    # FP-bait: an authenticated mode must not fire.
    (tmp_path / "T.java").write_text(
        'class T { void m() { Cipher.getInstance("AES/GCM/NoPadding"); } }\n', encoding="utf-8"
    )
    assert JavaWeakCryptoGuard().run(tmp_path, _javaprof(tmp_path)) == []


def test_java_weak_crypto_silent_in_comment(tmp_path: Path) -> None:
    # FP-bait: an example mentioned in a `//` comment must not fire.
    (tmp_path / "T.java").write_text(
        'class T { void m() { // MessageDigest.getInstance("MD5") is bad\n'
        "int real = 1; } }\n",
        encoding="utf-8",
    )
    assert JavaWeakCryptoGuard().run(tmp_path, _javaprof(tmp_path)) == []


def test_java_weak_crypto_pragma_silences(tmp_path: Path) -> None:
    (tmp_path / "T.java").write_text(
        'class T { void m() { MessageDigest.getInstance("MD5"); // security: allow-weak-crypto\n} }\n',
        encoding="utf-8",
    )
    assert JavaWeakCryptoGuard().run(tmp_path, _javaprof(tmp_path)) == []


def test_java_weak_crypto_not_applicable_without_java() -> None:
    prof = mkprofile(Path("/tmp"), features={"python"})
    assert JavaWeakCryptoGuard().applies(prof) is False


def test_java_weak_crypto_ignores_javadoc_block_comment(tmp_path: Path) -> None:
    # FP-bait for the /** */ handling in strip_java_comments: an example inside a real
    # Javadoc block comment must not fire.
    (tmp_path / "T.java").write_text(
        '/**\n * MessageDigest.getInstance("MD5") is an example, do not use\n */\n'
        "class T { void m() { int real = 1; } }\n",
        encoding="utf-8",
    )
    assert JavaWeakCryptoGuard().run(tmp_path, _javaprof(tmp_path)) == []


def test_java_weak_crypto_skips_maven_test_tree(tmp_path: Path) -> None:
    # Narrowing gate (PR #839 review): Maven/Gradle put test sources under `src/test/java`, whose
    # `test` segment `is_nonproduct_path` reads as non-product. Both trees carry the SAME violation
    # in one run, so this pins the skip AND the direction traded against it — production code under
    # `src/main/java` must still fire.
    src = (
        'class T { void m() { MessageDigest.getInstance("MD5"); } }\n'
    )
    for tree in ("main", "test"):
        d = tmp_path / "src" / tree / "java"
        d.mkdir(parents=True)
        (d / "T.java").write_text(src, encoding="utf-8")
    findings = JavaWeakCryptoGuard().run(tmp_path, _javaprof(tmp_path))
    assert findings
    assert {f.location.split(":")[0].replace("\\", "/") for f in findings} == {"src/main/java/T.java"}


def test_java_weak_crypto_pragma_quoted_in_a_string_does_not_suppress(tmp_path: Path) -> None:
    # #424 E4: the per-line check reads the same-length Java comment-only view, so a string on the
    # finding's own line quoting the pragma is content - only a real `//` comment opts out.
    (tmp_path / "T.java").write_text(
        'class T { void m() { String d = "add // security: allow-weak-crypto"; '
        'MessageDigest.getInstance("MD5"); } }\n',
        encoding="utf-8",
    )
    assert len(JavaWeakCryptoGuard().run(tmp_path, _javaprof(tmp_path))) == 1
