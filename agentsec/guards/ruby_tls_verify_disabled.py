"""Guard: TLS certificate verification disabled in Ruby HTTP/OpenSSL clients (checklist §8).

The Ruby counterpart to agentsec's existing `tls-verify-disabled` (Python/Express) and
`go-tls-verify-disabled` (Go) guards — same requirement (an outbound HTTPS call that does not
validate the peer certificate is a man-in-the-middle waiting to happen), a genuinely different
code surface (Ruby's `OpenSSL::SSL::VERIFY_NONE` constant against a `verify_mode` slot instead
of `verify=False` / `InsecureSkipVerify: true`), so it extends the same `8-tls-verify-disabled`
checklist item rather than duplicating it.

Pattern verified against Brakeman's real source (`lib/brakeman/checks/check_ssl_verify.rb`,
`Brakeman::CheckSSLVerify`) — the class name and file are cited for provenance; detection logic
and test fixtures here are original, developed independently against the pattern description,
not copied or derived from Brakeman's own (Ruby) implementation.

Fires HIGH on `OpenSSL::SSL::VERIFY_NONE` reaching a `verify_mode` slot, in any of the three
shapes real Ruby code writes it:

  * **Bare assignment** — `verify_mode = OpenSSL::SSL::VERIFY_NONE`, e.g. inside an
    `OpenSSL::SSL::SSLContext.new.tap { |ctx| ... }` block or a config builder.
  * **Receiver-attribute assignment** — `http.verify_mode = OpenSSL::SSL::VERIFY_NONE`, the
    `Net::HTTP` instance setter (`http = Net::HTTP.new(host, 443); http.use_ssl = true; ...`).
    By far the most common shape in real Ruby apps.
  * **Keyword-argument / hash form** — `Net::HTTP.start(host, port, use_ssl: true,
    verify_mode: OpenSSL::SSL::VERIFY_NONE)`, the `:verify_mode => ...` hash-rocket spelling,
    and the Rails mailer variant `smtp_settings = { openssl_verify_mode: OpenSSL::SSL::VERIFY_NONE }`
    (any `<prefix>_verify_mode` key resolves to the same OpenSSL setting).

The key is matched at its own boundary but allows an underscore-prefixed variant, so
`openssl_verify_mode:`/`ssl_verify_mode =` fire too. The RHS is anchored to the fully-qualified
constant `OpenSSL::SSL::VERIFY_NONE` (an optional leading `::`), which has exactly one meaning
in Ruby: accept any certificate, or none.

`VERIFY_PEER` (the correct value) and a *comparison* against `VERIFY_NONE` — the defensive
`raise if ctx.verify_mode == OpenSSL::SSL::VERIFY_NONE` shape, which is a security check, not a
violation — are both deliberately silent: the operator alternation accepts `=`, `=>` and `:`
but never `==`/`=~`.

Suppress an audited case (e.g. a genuinely self-signed internal endpoint the app has no other
way to reach yet) with:

    http.verify_mode = OpenSSL::SSL::VERIFY_NONE  # security: allow-ruby-tls-verify-disabled
"""
from __future__ import annotations

import re
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import CanaryPlant, Guard, comment_view, iter_files, read, rel, ruby_scan_dirs, strip_ruby_comments

_STANDARDS = ["CWE-295"]

# `verify_mode` (or an underscore-prefixed variant like `openssl_verify_mode`/`ssl_verify_mode`)
# receiving `OpenSSL::SSL::VERIFY_NONE`. The three accepted operators are Ruby's three ways of
# putting a value in that slot:
#   `=`  assignment          — `verify_mode = ...` / `http.verify_mode = ...`
#   `:`  keyword / hash key  — `Net::HTTP.start(..., verify_mode: ...)`
#   `=>` hash rocket         — `{ :verify_mode => ... }`
# `=(?![=~>])` keeps a COMPARISON (`== OpenSSL::SSL::VERIFY_NONE`, i.e. code checking that
# verification is NOT off) and the `=~` match operator out — those are not violations.
# The left boundary `(?<![A-Za-z0-9_])` lets `.verify_mode`/`:verify_mode` through while the
# optional `[A-Za-z0-9_]+_` prefix group is what admits `openssl_verify_mode`.
_VERIFY_MODE_NONE = re.compile(
    r"(?<![A-Za-z0-9_])(?:[A-Za-z0-9_]+_)?verify_mode\s*(?:=>|:|=(?![=~>]))\s*"
    r"(?:::)?OpenSSL::SSL::VERIFY_NONE(?![A-Za-z0-9_])"
)

_PRAGMA = re.compile(r"#\s*security:\s*allow-ruby-tls-verify-disabled")

_MESSAGE = (
    "OpenSSL::SSL::VERIFY_NONE disables TLS certificate verification on this connection — the "
    "app accepts any certificate, or none at all, with no check that the peer is the intended "
    "host and no check that its certificate chains to a trusted root. A man-in-the-middle "
    "attacker anywhere on the network path can intercept and tamper with the traffic "
    "undetected (CWE-295)."
)
_REMEDIATION = (
    "Use OpenSSL::SSL::VERIFY_PEER (the default) and fix the underlying certificate issue: "
    "point `ca_file`/`ca_path` at the correct CA bundle, or add a genuinely private internal "
    "CA to the trust store, instead of turning verification off. Suppress with "
    "`# security: allow-ruby-tls-verify-disabled` only after confirming there is no "
    "alternative (e.g. a fully offline/internal-only connection)."
)


class RubyTlsVerifyDisabledGuard(Guard):
    id = "ruby-tls-verify-disabled"
    title = "TLS certificate verification disabled (OpenSSL::SSL::VERIFY_NONE)"
    area = "Crypto & TLS"

    # ruby_http_client.rb: http.verify_mode = OpenSSL::SSL::VERIFY_NONE ->
    # ruby-tls-verify-disabled/verify-mode-none.
    canary_plant = CanaryPlant(
        files={
            "ruby_http_client.rb": (
                "require 'net/http'\n\n"
                "def fetch(uri)\n"
                "  http = Net::HTTP.new(uri.host, uri.port)\n"
                "  http.use_ssl = true\n"
                "  http.verify_mode = OpenSSL::SSL::VERIFY_NONE\n"
                "  http.get(uri.path)\n"
                "end\n"
            ),
        },
        expects=frozenset({"ruby-tls-verify-disabled/verify-mode-none"}),
    )

    def applies(self, profile: StackProfile) -> bool:
        return "ruby" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []
        seen: set[Path] = set()
        for d in ruby_scan_dirs(root, profile):
            for f in iter_files(d, (".rb",)):
                if f in seen:
                    continue
                seen.add(f)
                out.extend(self._scan(root, f))
        return out

    def _scan(self, root: Path, f: Path) -> list[Finding]:
        out: list[Finding] = []
        text = read(f)
        # Two parallel views of the same file (the ruby_weak_crypto.py shape): the pattern check
        # runs against the COMMENT-STRIPPED line so a documented example inside a `#` note or a
        # `=begin`/`=end` block never fires, while the pragma check runs against the COMMENT-ONLY view of the line (#424) —
        # the pragma IS a comment, so `strip_ruby_comments` blanks it and a check against the
        # stripped copy would always miss it.
        view_lines = comment_view(text, "ruby").splitlines()  # same length: comments only (#424)
        # `strip_ruby_comments` preserves the splitlines() count exactly (its own tested
        # invariant), so the two lists always pair up — `strict=True` documents that invariant
        # rather than silently truncating and misaligning every line number after a break.
        code_lines = strip_ruby_comments(text).splitlines()
        for lineno, (view, line) in enumerate(zip(view_lines, code_lines, strict=True), start=1):
            if _PRAGMA.search(view):
                continue
            if _VERIFY_MODE_NONE.search(line):
                out.append(self._finding(root, f, lineno))
        return out

    def _finding(self, root: Path, f: Path, lineno: int) -> Finding:
        return Finding(
            check_id=self.id,
            severity="high",
            title=self.title,
            location=f"{rel(root, f)}:{lineno}",
            message=_MESSAGE,
            remediation=_REMEDIATION,
            rule="ruby-tls-verify-disabled/verify-mode-none",
            standards=list(_STANDARDS),
        )
