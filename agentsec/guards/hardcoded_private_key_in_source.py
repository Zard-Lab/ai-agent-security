"""Guard: hardcoded/committed private key material in source (checklist §8, new item).

    -----BEGIN RSA PRIVATE KEY-----
    MIIEowIBAAKCAQEA1c7+9z5Pad7OejecsQ0bu3Fh22Eq...
    -----END RSA PRIVATE KEY-----

A literal PEM private-key header committed anywhere in the repo (`-----BEGIN`, an optional
uppercase key-type label, then `PRIVATE KEY` and the closing dashes) means real
cryptographic key material has been checked into version control. This is CWE-321 (Use of
Hard-coded Cryptographic Key), OWASP:A04: whoever can read the repo (every contributor, every
CI log, every fork, every scraped public mirror) can use whatever the key authenticates — SSH
access, TLS termination, a signing key, a service credential. Once committed, the key must be
treated as compromised and rotated; deleting the file does not remove it from git history.

Ported from drogonsec's `GEN-001` generic rule (`filipi86/drogonsec`, verified against its Go
source), which flags this pattern across ANY language — a PEM header is not Python-specific or
JS-specific. This guard is deliberately generic: `applies()` returns True unconditionally, and
`run()` scans every non-vendored file in the repo (not just source-code suffixes), because a
leaked key is just as real sitting in a `.env`, a Terraform `.tfvars`, a Kubernetes Secret
manifest, or a stray `id_rsa` copy as it is inside a `.py` file. Test/fixture paths are
deliberately NOT exempted the way other guards exempt them (via `is_nonproduct_path`) — real key
material committed under `tests/` or `fixtures/` is still a real leaked key, arguably a MORE
common way this actually happens (a developer drops a real key into a fixture "just to make the
test pass" and forgets to rotate/regenerate it).

Fires CRITICAL on any line carrying a complete literal PEM private-key marker: `BEGIN`, an
optional uppercase key-type label, `PRIVATE KEY`, and the required closing `-----`. The
false-positive surface is near-zero: a complete PEM header only appears when real key material is
present. Requiring the closing delimiter excludes an instructional doc that mentions the header
label in prose without it (`Copy the content including the -----BEGIN OPENSSH PRIVATE KEY`), which
otherwise produced a critical from a mere doc mention (round-2 §E.1). A header inside a COMMENT
still fires: a real PEM key committed in a `#`/`//` comment (or a commented-out key block) is
still leaked key material, since commenting it out does not remove it from the repo or git
history — the false-negative cost of hiding a real commented key outweighs the rare docs-example
false positive (which the pragma below covers). The one same-line anti-pattern kept is a runtime-built string
(`.append("-----BEGIN...")`, the shape PEM-*generating* cert/test utilities use to emit a header
they are creating, not embedding). It is matched only against the text BEFORE the header, so an
unrelated TRAILING `//`/`https://` comment can never suppress a real committed key.

A second same-line check (found scanning a real deployment guide): a doc naming BOTH complete
headers in one sentence (`Copy ... including the -----BEGIN OPENSSH PRIVATE KEY----- and
-----END OPENSSH PRIVATE KEY----- lines.`) has closing dashes on both markers, so §E.1's rule alone
does not exclude it. Discriminator: prose between two quoted headers is ordinary words broken up by
spaces, so it never contains one long unbroken run of base64/PEM alphabet characters; a real key's
body — even a single-line, space-flattened or `\n`-escaped one (the common `.env`/JSON shape,
`PRIVATE_KEY="-----BEGIN...-----\nMIIE...\n-----END...-----"`, or a copy-paste/`tr '\n' ' '`
reflow that turns the embedded newlines into literal spaces) — always does, whatever it was joined
with. So a same-line BEGIN+END pair is suppressed only when NO run of 40+ base64/PEM-alphabet
characters appears between the markers; a real key (any joiner, even one with incidental spaces in
it) still has such a run and still fires. An earlier version of this check tested for "any space
between the markers" instead, which silently suppressed exactly the space-flattened/reflowed real-key
shapes above (round-3 fix, PR #728 review) — the base64-run test targets the actual thing that
distinguishes key material from prose, not an incidental byproduct of one particular prose style.
A doc example shown as a normal multi-line block (BEGIN on its own line, body, END on its own
line) is untouched by this — that case remains the accepted docs-example false positive above,
same as a single bare BEGIN header with no END anywhere on the same line.

Suppress an audited/intentional case (e.g. a documented decoy fixture) with
`# security: allow-hardcoded-private-key` on the offending line.

Bounded reads (#443). Because the walk is unfiltered, a scanned file can be a multi-GB committed
model checkpoint or dataset. Reading one whole peaked at about 7x its size, and an out-of-memory
error there would have discarded every finding the guard had already collected. A file up to 1 MiB
is still read whole. A larger one is first byte-scanned for `-----BEGIN` across the WHOLE file in
O(chunk) memory, so nothing is skipped or head-truncated. Only if that hits is the file
line-streamed, with each line capped at 1 MiB; the same line boundaries and numbering apply, and
the same per-line rules run on each line. A line over the cap is checked in overlapping pieces.
Any residual difference from a whole-line check fires in the safe direction: a second header on
the same line can be reported, or a header whose `append(` prefix fell into the previous piece.
"""
from __future__ import annotations

import re
from collections.abc import Iterable
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding
from agentsec.walk import walk_files

from .base import CanaryPlant, Guard, file_contains_bytes, iter_lines_bounded, pragma_present, read, rel

# The literal PEM private-key header, REQUIRING the closing `-----` delimiter, so the match is a
# complete `-----BEGIN [TYPE ]PRIVATE KEY[ BLOCK]-----` header as it appears in every real key, not a
# bare `-----BEGIN ... PRIVATE KEY` fragment. That trailing `-----` is what a real committed key always
# carries and what a PROSE MENTION drops: an instructional doc ("Copy the content including the
# `-----BEGIN OPENSSH PRIVATE KEY`") quotes the label without the closing delimiter, so it no longer
# produces a critical (round-2 §E.1). Real key material (full PEM blocks, and single-line
# `SSH_KEY=-----BEGIN ... PRIVATE KEY-----` value assignments) keeps the closing dashes and still fires.
#
# The key-type label is a BOUNDED CHARACTER CLASS, not an enumeration of spellings. It was
# `(?:RSA |EC |DSA |OPENSSH |PGP )?` until #575: a closed list inherited from the drogonsec GEN-001
# rule this guard was ported from, and that list shipped TWO false negatives on a CRITICAL guard.
# First PGP armored keys (PR #479, closed by the `(?: BLOCK)?` below), then every remaining OpenSSL
# label at once: `ENCRYPTED PRIVATE KEY` (PKCS#8), `ANY PRIVATE KEY`, `SM2 PRIVATE KEY`. The first of
# those is not exotic; it is what OpenSSL 3.x writes BY DEFAULT when a key of ANY algorithm is
# password-protected, and what `ssh-keygen -m PKCS8` writes. You have to pass `-traditional` to get a
# spelling the old list covered. What makes a line a private-key header is the `PRIVATE KEY` marker
# plus the closing dashes, not which label precedes it, so matching that is both more correct and the
# only version that does not rot: under an enumeration every label the world defines is a silent miss
# by default. The nine labels this covers (`PEM_STRING_*` in openssl/pem.h, plus OpenSSH and RFC 4880
# armor) carry one test-table row each, so a tenth cannot be added silently.
#
# `{0,20}` is bounded on purpose: it sits between two literal anchors, so it adds no backtracking
# surface (measured linear, ~1ms against a 1MB adversarial line). An unbounded quantifier here would
# be precisely the shape #676/#697 are sweeping out. The class is UPPERCASE-only and there is
# deliberately no `re.I`, because real PEM labels are uppercase, a lowercase spelling is prose rather
# than key material, and case-folding would re-open the §E.1 doc-mention false-positive class this
# guard already fought once. The PUBLIC half of the same header space (`PUBLIC KEY`, `RSA PUBLIC KEY`,
# `PGP PUBLIC KEY BLOCK`) is excluded for free, since none of it contains `PRIVATE KEY`.
#
# The `(?: BLOCK)?` is load-bearing: PGP armored private keys carry the word `BLOCK` between
# `PRIVATE KEY` and the closing dashes (the `BEGIN PGP PRIVATE KEY BLOCK` armor header). Without it the
# closing-delimiter requirement would silently stop detecting real committed PGP keys (PR #479 review).
# (Note: PEM labels are written throughout this file WITHOUT their leading `-----` on purpose, so this
# guard does not fire on its own source comments during the dogfood self-audit.) Anchoring on
# "-----BEGIN" also keeps the fast pre-filter below provably safe.
_PEM_HEADER = re.compile(r"-----BEGIN [A-Z0-9 ]{0,20}PRIVATE KEY(?: BLOCK)?-----")

# The closing half of the same header, used ONLY for the same-line-prose check below — this
# guard still fires on a bare BEGIN header with no END in sight (a real key's body is usually on
# the following lines, which this line-by-line scan never needs to see).
_PEM_END_HEADER = re.compile(r"-----END [A-Z0-9 ]{0,20}PRIVATE KEY(?: BLOCK)?-----")

# Same-line BEGIN...END noise suppressor: an instructional doc naming BOTH complete headers in one
# sentence (`Copy ... including the -----BEGIN OPENSSH PRIVATE KEY----- and -----END OPENSSH
# PRIVATE KEY----- lines.`) — found scanning a real deployment guide, and NOT excluded by the
# existing closing-dashes requirement (§E.1), since this line has the closing dashes on both
# markers. Discriminator: prose between two quoted headers is ordinary words separated by spaces —
# it never contains one long unbroken run of base64/PEM-alphabet characters. A real key's body
# always does, regardless of how its embedded newlines were joined (`\n`-escaped, space-flattened
# by a copy-paste/`tr '\n' ' '` reflow, tab-joined, ...). An earlier version of this discriminator
# tested for "any space between the markers", which silently suppressed exactly the
# space-flattened/reflowed real-key shapes (round-3 fix, PR #728 review) — this test targets the
# actual thing that distinguishes key material from prose instead of an incidental byproduct of one
# particular prose style. 40 is comfortably below any real base64-encoded key segment's natural
# line length (~64 chars) and comfortably above anything a normal English sentence produces as one
# unbroken run. Known, accepted residual: `.search()` only needs ONE 40+ run anywhere in the gap,
# so this stays correct even with a stray space splitting the body, UNLESS every resulting segment
# is itself under 40 chars — which needs both a pathologically short key body (well under one PEM
# line) AND an unlucky split point, not the ordinary "one accidental space" case this fix targets.
_B64_RUN = re.compile(r"[A-Za-z0-9+/=]{40,}")

# Same-line noise suppressor: a runtime-built PEM header string (`.append("-----BEGIN...")`, the
# shape PEM-*generating* cert/test utilities use to emit a header they are creating, not embedding
# committed key material). Matched against the prefix (text BEFORE the header) and anchored to its
# END (`...(\s*["']?$`), so it fires only when the `append("`/`append('` opens the string the header
# begins — an unrelated earlier `.append(...)` call elsewhere on the line does NOT suppress a real
# key that follows it. A COMMENT is deliberately NOT a suppressor: a real PEM header committed inside
# a `#`/`//` comment (or a commented-out key block) is still leaked key material — commenting it out
# does not remove it from the repo or git history — so it must flag. The false-negative cost of
# hiding a real commented key outweighs the rare docs-example false positive, which the explicit
# `# security: allow-hardcoded-private-key` pragma already covers.
# Not `\s*["']?\s*$` (issue #985): two adjacent `\s*` separated by an OPTIONAL quote means an
# unterminated whitespace run of length N can split between them N ways, each retried when `$`
# fails against the PEM header text that follows — O(N^2) (measured 23.8s at n=64k spaces).
# Folding the second `\s*` into the optional-quote group removes the ambiguity: whitespace after
# `(` is consumed once, and a second run is only reachable behind an actual quote.
_ANTI_PATTERN = re.compile(r"""\bappend\s*\(\s*(?:["']\s*)?$""", re.IGNORECASE)

# Matched on the raw line by contract (`dialect=None`, #1040 T5), in every file type. What this guard
# flags is itself string content: in source, a key literal spanning lines (`KEY = """-----BEGIN …`)
# puts the flagged line inside the string, where no comment can go, so a comment view would void
# that opt-out (rule 4). The other file types it reads (`.pem`, `.md`, JSON) have no comment syntax.
_PRAGMA = re.compile(r"#\s*security:\s*allow-hardcoded-private-key")

_STANDARDS = ["CWE-321", "OWASP:A04"]

# Bounded read (#443). A file up to `_FULL_READ_MAX_BYTES` is read whole, as it always was; every real
# key file, `.env`, `.tfvars` and manifest is far below it. A larger one is byte-scanned for the
# `-----BEGIN` pre-filter and, only if that hits, line-streamed with each line capped at
# `_MAX_LINE_CHARS`. The overlap between the pieces of an overlong line must exceed the longest
# header (about 55 bytes) plus the `append("` look-behind; 4 KiB also keeps a whole RSA-4096 body
# (about 3.2 KB) together with its END marker for the same-line prose check.
_FULL_READ_MAX_BYTES = 1 << 20
_MAX_LINE_CHARS = 1 << 20
_LINE_OVERLAP_CHARS = 4096


def _line_marker(line: str) -> str | None:
    """The first PEM private-key header on `line`, or None if there is none or it is suppressed."""
    m = _PEM_HEADER.search(line)
    if not m:
        return None
    # Suppress only when an append marker PRECEDES the header (prefix), so a real key is never
    # swallowed by an unrelated trailing `//`/`https://` comment.
    if _ANTI_PATTERN.search(line[: m.start()]):
        return None
    end_m = _PEM_END_HEADER.search(line, m.end())
    if end_m and not _B64_RUN.search(line[m.end() : end_m.start()]):
        return None
    return m.group(0)


class HardcodedPrivateKeyInSourceGuard(Guard):
    id = "hardcoded-private-key-in-source"
    title = "Hardcoded/committed private key material in source"
    area = "Secrets"

    # leaked_key.pem: a real-shaped RSA PEM private key header -> fires
    # hardcoded-private-key-in-source. Must NOT contain: allow-hardcoded-private-key pragma.
    canary_plant = CanaryPlant(
        files={
            "leaked_key.pem": (
                "-----BEGIN RSA PRIVATE KEY-----\n"
                "MIIEpAIBAAKCAQEA1234567890canaryplaceholderkeymaterial1234567890\n"
                "-----END RSA PRIVATE KEY-----\n"
            ),
        },
        expects=frozenset({
            "hardcoded-private-key-in-source/pem-header-literal",
        }),
    )

    def applies(self, profile: StackProfile) -> bool:  # noqa: ARG002
        # Generic across every language/config format — a PEM header can appear anywhere,
        # regardless of the detected stack.
        return True

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:  # noqa: ARG002
        out: list[Finding] = []
        for f in walk_files(root):
            out.extend(self._scan(root, f))
        return out

    def _scan(self, root: Path, f: Path) -> list[Finding]:
        # Bounded read (#443): the walk is unfiltered, so `f` may be a multi-GB model checkpoint.
        try:
            size = f.stat().st_size
        except OSError:
            return []
        lines: Iterable[tuple[int, str]]
        if size <= _FULL_READ_MAX_BYTES:
            text = read(f)
            if "-----BEGIN" not in text:  # cheap pre-filter: the regex can never match without this
                return []
            lines = enumerate(text.splitlines(), start=1)
        else:
            # The same pre-filter over the raw bytes of the WHOLE file, in O(chunk) memory. A miss
            # is not a skip: every finding needs these bytes, so there is nothing left to disclose.
            if not file_contains_bytes(f, b"-----BEGIN"):
                return []
            lines = iter_lines_bounded(
                f, max_line_chars=_MAX_LINE_CHARS, overlap_chars=_LINE_OVERLAP_CHARS
            )
        return self._scan_lines(root, f, lines)

    def _scan_lines(self, root: Path, f: Path, lines: Iterable[tuple[int, str]]) -> list[Finding]:
        # One verdict per LOGICAL line. A line over `_MAX_LINE_CHARS` (large-file path only) arrives
        # as several overlapping pieces with one line number: it reports its first unsuppressed
        # header, and a pragma on ANY piece of it silences the line, as it would on a whole line.
        out: list[Finding] = []
        cur = 0
        marker: str | None = None
        pragma = False
        for lineno, line in lines:
            if lineno != cur:
                if marker and not pragma:
                    out.append(self._finding(root, f, cur, marker))
                cur, marker, pragma = lineno, None, False
            # The substring tests are the literals each regex needs: cheap on a large file's lines.
            if "allow-hardcoded-private-key" in line and pragma_present(_PRAGMA, line, dialect=None):
                pragma = True
            if marker is None and "-----BEGIN" in line:
                marker = _line_marker(line)
        if marker and not pragma:
            out.append(self._finding(root, f, cur, marker))
        return out

    def _finding(self, root: Path, f: Path, lineno: int, marker: str) -> Finding:
        return Finding(
            check_id=self.id,
            severity="critical",
            title=self.title,
            location=f"{rel(root, f)}:{lineno}",
            message=(
                f"This line contains `{marker}...`, a literal PEM private-key header — real "
                "cryptographic key material appears to be committed to version control. Anyone "
                "who can read this repo (contributors, CI logs, forks, scraped mirrors) can use "
                "this key, and git history retains it even after the file is deleted."
            ),
            remediation=(
                "Remove the key from the repo and rotate/reissue it immediately — treat it as "
                "compromised regardless of deletion, since git history still holds it. Store "
                "keys in a secrets manager or an untracked, gitignored file instead. Suppress an "
                "audited/intentional case (e.g. a documented decoy fixture) with "
                "`# security: allow-hardcoded-private-key` on the offending line."
            ),
            rule="hardcoded-private-key-in-source/pem-header-literal",
            standards=list(_STANDARDS),
        )
