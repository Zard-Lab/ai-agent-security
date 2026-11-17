from __future__ import annotations

from agentsec.guards.ruby_weak_crypto import RubyWeakCryptoGuard
from tests.guards._common import *  # noqa: F401,F403


def test_ruby_weak_crypto_flags_digest_md5(tmp_path: Path) -> None:
    (tmp_path / "checksum.rb").write_text(
        "require 'digest'\n\ndef checksum(data)\n  Digest::MD5.hexdigest(data)\nend\n",
        encoding="utf-8",
    )
    findings = RubyWeakCryptoGuard().run(tmp_path, _rbprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "ruby-weak-crypto/insecure-hash"
    assert findings[0].severity == "high"


def test_ruby_weak_crypto_flags_digest_sha1(tmp_path: Path) -> None:
    (tmp_path / "t.rb").write_text("Digest::SHA1.hexdigest(data)\n", encoding="utf-8")
    findings = RubyWeakCryptoGuard().run(tmp_path, _rbprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "ruby-weak-crypto/insecure-hash"


def test_ruby_weak_crypto_flags_openssl_digest_const_form(tmp_path: Path) -> None:
    (tmp_path / "t.rb").write_text("digest = OpenSSL::Digest::MD5.new\n", encoding="utf-8")
    findings = RubyWeakCryptoGuard().run(tmp_path, _rbprof(tmp_path))
    assert len(findings) == 1


def test_ruby_weak_crypto_flags_openssl_digest_string_form(tmp_path: Path) -> None:
    (tmp_path / "t.rb").write_text('digest = OpenSSL::Digest.new("SHA1")\n', encoding="utf-8")
    findings = RubyWeakCryptoGuard().run(tmp_path, _rbprof(tmp_path))
    assert len(findings) == 1


def test_ruby_weak_crypto_silent_on_sha256(tmp_path: Path) -> None:
    # FP-bait: a modern, non-broken digest must not fire.
    (tmp_path / "t.rb").write_text("Digest::SHA256.hexdigest(data)\n", encoding="utf-8")
    assert RubyWeakCryptoGuard().run(tmp_path, _rbprof(tmp_path)) == []


def test_ruby_weak_crypto_silent_in_comment(tmp_path: Path) -> None:
    # FP-bait: an example mentioned in a `#` comment must not fire.
    (tmp_path / "t.rb").write_text(
        "# Don't use Digest::MD5.hexdigest(data) here\nreal = 1\n", encoding="utf-8"
    )
    assert RubyWeakCryptoGuard().run(tmp_path, _rbprof(tmp_path)) == []


def test_ruby_weak_crypto_pragma_silences(tmp_path: Path) -> None:
    (tmp_path / "t.rb").write_text(
        "Digest::MD5.hexdigest(data)  # security: allow-weak-crypto\n", encoding="utf-8"
    )
    assert RubyWeakCryptoGuard().run(tmp_path, _rbprof(tmp_path)) == []


def test_ruby_weak_crypto_not_applicable_without_ruby() -> None:
    prof = mkprofile(Path("/tmp"), features={"python"})
    assert RubyWeakCryptoGuard().applies(prof) is False


def test_ruby_weak_crypto_ignores_begin_end_block_comment(tmp_path: Path) -> None:
    # FP-bait for the =begin/=end handling in strip_ruby_comments: an example inside a real
    # Ruby block comment must not fire.
    (tmp_path / "t.rb").write_text(
        "=begin\nDigest::MD5.hexdigest(data) is an example, do not use\n=end\nreal = 1\n",
        encoding="utf-8",
    )
    assert RubyWeakCryptoGuard().run(tmp_path, _rbprof(tmp_path)) == []


def test_ruby_weak_crypto_pragma_quoted_in_a_string_does_not_suppress(tmp_path: Path) -> None:
    # #424 E4: the per-line check reads the same-length Ruby comment-only view, so a string on the
    # finding's own line quoting the pragma is content - only a real `#` comment opts out.
    (tmp_path / "t.rb").write_text(
        'doc = "add # security: allow-weak-crypto"; Digest::MD5.hexdigest(data)\n', encoding="utf-8"
    )
    assert len(RubyWeakCryptoGuard().run(tmp_path, _rbprof(tmp_path))) == 1
