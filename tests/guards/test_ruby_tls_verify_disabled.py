from __future__ import annotations

from agentsec.guards.ruby_tls_verify_disabled import RubyTlsVerifyDisabledGuard
from tests.guards._common import *  # noqa: F401,F403


def test_ruby_tls_verify_disabled_flags_net_http_receiver_attr(tmp_path: Path) -> None:
    # The canary-plant shape: a Net::HTTP instance's own verify_mode setter.
    (tmp_path / "client.rb").write_text(
        "require 'net/http'\n\n"
        "def fetch(uri)\n"
        "  http = Net::HTTP.new(uri.host, uri.port)\n"
        "  http.use_ssl = true\n"
        "  http.verify_mode = OpenSSL::SSL::VERIFY_NONE\n"
        "  http.get(uri.path)\n"
        "end\n",
        encoding="utf-8",
    )
    findings = RubyTlsVerifyDisabledGuard().run(tmp_path, _rbprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "ruby-tls-verify-disabled/verify-mode-none"
    assert findings[0].severity == "high"
    assert findings[0].location == "client.rb:6"


def test_ruby_tls_verify_disabled_flags_bare_assignment(tmp_path: Path) -> None:
    (tmp_path / "t.rb").write_text(
        "ctx = OpenSSL::SSL::SSLContext.new\nverify_mode = OpenSSL::SSL::VERIFY_NONE\n",
        encoding="utf-8",
    )
    findings = RubyTlsVerifyDisabledGuard().run(tmp_path, _rbprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "ruby-tls-verify-disabled/verify-mode-none"


def test_ruby_tls_verify_disabled_flags_net_http_start_kwarg(tmp_path: Path) -> None:
    (tmp_path / "t.rb").write_text(
        "Net::HTTP.start(host, port, use_ssl: true, verify_mode: OpenSSL::SSL::VERIFY_NONE) do |http|\n"
        "  http.request(req)\n"
        "end\n",
        encoding="utf-8",
    )
    assert len(RubyTlsVerifyDisabledGuard().run(tmp_path, _rbprof(tmp_path))) == 1


def test_ruby_tls_verify_disabled_flags_kwarg_split_across_lines(tmp_path: Path) -> None:
    # Real Ruby wraps a long Net::HTTP.start call; the kwarg lands on its own line, away from
    # the `Net::HTTP.start(` token. Detection is anchored on the verify_mode slot, not the
    # receiver, so it still fires (and reports the kwarg's own line).
    (tmp_path / "t.rb").write_text(
        "Net::HTTP.start(host, port,\n"
        "                use_ssl: true,\n"
        "                verify_mode: OpenSSL::SSL::VERIFY_NONE) do |http|\n"
        "  http.request(req)\n"
        "end\n",
        encoding="utf-8",
    )
    findings = RubyTlsVerifyDisabledGuard().run(tmp_path, _rbprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].location == "t.rb:3"


def test_ruby_tls_verify_disabled_flags_hash_rocket_form(tmp_path: Path) -> None:
    (tmp_path / "t.rb").write_text(
        "opts = { :use_ssl => true, :verify_mode => OpenSSL::SSL::VERIFY_NONE }\n",
        encoding="utf-8",
    )
    assert len(RubyTlsVerifyDisabledGuard().run(tmp_path, _rbprof(tmp_path))) == 1


def test_ruby_tls_verify_disabled_flags_rails_mailer_openssl_verify_mode(tmp_path: Path) -> None:
    # The Rails ActionMailer smtp_settings spelling of the same OpenSSL setting.
    (tmp_path / "t.rb").write_text(
        "config.action_mailer.smtp_settings = {\n"
        "  address: 'smtp.example.com',\n"
        "  openssl_verify_mode: OpenSSL::SSL::VERIFY_NONE\n"
        "}\n",
        encoding="utf-8",
    )
    assert len(RubyTlsVerifyDisabledGuard().run(tmp_path, _rbprof(tmp_path))) == 1


def test_ruby_tls_verify_disabled_silent_on_verify_peer(tmp_path: Path) -> None:
    # FP-bait: the CORRECT value must not fire, in either the assignment or the kwarg form.
    (tmp_path / "t.rb").write_text(
        "http.verify_mode = OpenSSL::SSL::VERIFY_PEER\n"
        "Net::HTTP.start(host, port, use_ssl: true, verify_mode: OpenSSL::SSL::VERIFY_PEER)\n",
        encoding="utf-8",
    )
    assert RubyTlsVerifyDisabledGuard().run(tmp_path, _rbprof(tmp_path)) == []


def test_ruby_tls_verify_disabled_silent_on_defensive_comparison(tmp_path: Path) -> None:
    # FP-bait: code CHECKING that verification is not disabled is a security control, not a
    # violation. The operator alternation accepts `=`/`=>`/`:` but never `==`.
    (tmp_path / "t.rb").write_text(
        "raise 'insecure TLS config' if ctx.verify_mode == OpenSSL::SSL::VERIFY_NONE\n",
        encoding="utf-8",
    )
    assert RubyTlsVerifyDisabledGuard().run(tmp_path, _rbprof(tmp_path)) == []


def test_ruby_tls_verify_disabled_silent_on_unrelated_verify_mode(tmp_path: Path) -> None:
    # FP-bait: `verify_mode` is a plausible attribute name outside OpenSSL; the RHS is anchored
    # to the fully-qualified constant, so an unrelated value never fires.
    (tmp_path / "t.rb").write_text(
        "signature.verify_mode = :strict\ntoken.verify_mode = ENV['JWT_VERIFY_MODE']\n",
        encoding="utf-8",
    )
    assert RubyTlsVerifyDisabledGuard().run(tmp_path, _rbprof(tmp_path)) == []


def test_ruby_tls_verify_disabled_silent_in_comment(tmp_path: Path) -> None:
    # FP-bait: an example mentioned in a `#` comment must not fire.
    (tmp_path / "t.rb").write_text(
        "# http.verify_mode = OpenSSL::SSL::VERIFY_NONE  <- never do this\n"
        "http.verify_mode = OpenSSL::SSL::VERIFY_PEER\n",
        encoding="utf-8",
    )
    assert RubyTlsVerifyDisabledGuard().run(tmp_path, _rbprof(tmp_path)) == []


def test_ruby_tls_verify_disabled_ignores_begin_end_block_comment(tmp_path: Path) -> None:
    # FP-bait for the =begin/=end handling in strip_ruby_comments.
    (tmp_path / "t.rb").write_text(
        "=begin\n"
        "Never write http.verify_mode = OpenSSL::SSL::VERIFY_NONE in production.\n"
        "=end\n"
        "real = 1\n",
        encoding="utf-8",
    )
    assert RubyTlsVerifyDisabledGuard().run(tmp_path, _rbprof(tmp_path)) == []


def test_ruby_tls_verify_disabled_pragma_silences(tmp_path: Path) -> None:
    (tmp_path / "t.rb").write_text(
        "http.verify_mode = OpenSSL::SSL::VERIFY_NONE  # security: allow-ruby-tls-verify-disabled\n",
        encoding="utf-8",
    )
    assert RubyTlsVerifyDisabledGuard().run(tmp_path, _rbprof(tmp_path)) == []


def test_ruby_tls_verify_disabled_not_applicable_without_ruby() -> None:
    prof = mkprofile(Path("/tmp"), features={"python"})
    assert RubyTlsVerifyDisabledGuard().applies(prof) is False
