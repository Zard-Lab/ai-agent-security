from __future__ import annotations

import os
import tracemalloc

import pytest

import agentsec.guards.hardcoded_private_key_in_source as _hpk
from agentsec.guards.hardcoded_private_key_in_source import HardcodedPrivateKeyInSourceGuard
from tests._timing import assert_growth
from tests.guards._common import *  # noqa: F401,F403


def test_hardcoded_private_key_in_source_fires_on_rsa_pem(tmp_path: Path) -> None:
    (tmp_path / "id_rsa.py").write_text(
        "KEY = '''-----BEGIN RSA PRIVATE KEY-----\n"
        "MIIEowIBAAKCAQEA1c7+9z5Pad7OejecsQ0bu3Fh22Eq\n"
        "-----END RSA PRIVATE KEY-----'''\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path)
    findings = HardcodedPrivateKeyInSourceGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "hardcoded-private-key-in-source/pem-header-literal"
    assert findings[0].severity == "critical"
    assert findings[0].location == "id_rsa.py:1"


def test_hardcoded_private_key_in_source_fires_on_openssh_key_any_file(tmp_path: Path) -> None:
    # Generic: fires in a non-source config file too (a leaked key in `.env` is just as real).
    (tmp_path / "deploy.env").write_text(
        "SSH_KEY=-----BEGIN OPENSSH PRIVATE KEY-----\n", encoding="utf-8"
    )
    profile = mkprofile(tmp_path)
    findings = HardcodedPrivateKeyInSourceGuard().run(tmp_path, profile)
    assert len(findings) == 1


def test_hardcoded_private_key_in_source_fires_on_bare_private_key(tmp_path: Path) -> None:
    (tmp_path / "cert.pem").write_text(
        "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQ\n-----END PRIVATE KEY-----\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path)
    findings = HardcodedPrivateKeyInSourceGuard().run(tmp_path, profile)
    assert len(findings) == 1


def test_hardcoded_private_key_in_source_silent_on_comment_mentioning_private_key(
    tmp_path: Path,
) -> None:
    # FP-bait: a comment that mentions "PRIVATE KEY" without the dashed PEM header must not fire.
    (tmp_path / "notes.py").write_text(
        "# TODO: never commit a PRIVATE KEY to this repo, rotate immediately if found\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path)
    assert HardcodedPrivateKeyInSourceGuard().run(tmp_path, profile) == []


def test_hardcoded_private_key_in_source_silent_on_file_path_reference(tmp_path: Path) -> None:
    # FP-bait: a .pem/.key file PATH reference (not embedded key content) must not fire.
    (tmp_path / "loader.py").write_text(
        "with open('/etc/ssl/private/server.key') as f:\n"
        "    data = f.read()\n"
        "cert_path = 'certs/id_rsa.pem'\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path)
    assert HardcodedPrivateKeyInSourceGuard().run(tmp_path, profile) == []


def test_hardcoded_private_key_in_source_fires_on_commented_out_header(tmp_path: Path) -> None:
    # A real PEM header committed inside a `#`/`//` comment (or a commented-out key block) is
    # still leaked key material — commenting it out does not scrub it from the repo/git history —
    # so it MUST fire. The pragma is the escape hatch for a genuine docs example, not the comment.
    (tmp_path / "leaked.py").write_text(
        "# old deploy key, do not use:\n# -----BEGIN RSA PRIVATE KEY-----\n# MIIEowIBAAKCAQEA...\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path)
    findings = HardcodedPrivateKeyInSourceGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].severity == "critical"


def test_hardcoded_private_key_in_source_silent_on_runtime_built_string(tmp_path: Path) -> None:
    # FP-bait: a PEM-generating utility building the string at runtime via `.append(`.
    (tmp_path / "gen_cert.py").write_text(
        'buf.append("-----BEGIN RSA PRIVATE KEY-----\\n")\n', encoding="utf-8"
    )
    profile = mkprofile(tmp_path)
    assert HardcodedPrivateKeyInSourceGuard().run(tmp_path, profile) == []


def test_hardcoded_private_key_in_source_pragma_silences(tmp_path: Path) -> None:
    (tmp_path / "decoy.py").write_text(
        "KEY = '-----BEGIN RSA PRIVATE KEY-----'  # security: allow-hardcoded-private-key\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path)
    assert HardcodedPrivateKeyInSourceGuard().run(tmp_path, profile) == []


def test_hardcoded_private_key_in_source_fires_despite_trailing_url_comment(tmp_path: Path) -> None:
    # Regression (C1): a REAL committed key with a trailing comment containing a URL (`https://`
    # holds a `//`) must still fire. The anti-pattern is now tested only against the text BEFORE
    # the header, so an unrelated trailing `//` no longer swallows a genuine key.
    (tmp_path / "secrets.py").write_text(
        "PRIV = '-----BEGIN RSA PRIVATE KEY-----'  # rotate via https://vault.example.com\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path)
    findings = HardcodedPrivateKeyInSourceGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].severity == "critical"


def test_hardcoded_private_key_in_source_fires_on_header_with_trailing_c_comment(
    tmp_path: Path,
) -> None:
    # Regression (C1): a bare PEM header line with a trailing C-style `//` comment (common in
    # JS/TS/Go/Java source, which this generic guard scans) is real key material — must fire.
    (tmp_path / "deploy.js").write_text(
        "-----BEGIN OPENSSH PRIVATE KEY----- // deploy key, rotate before ship\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path)
    assert len(HardcodedPrivateKeyInSourceGuard().run(tmp_path, profile)) == 1


def test_hardcoded_private_key_in_source_fires_despite_unrelated_earlier_append(
    tmp_path: Path,
) -> None:
    # Regression (RH1): the `append(` suppressor is anchored to the END of the prefix, so an
    # unrelated earlier `.append(...)` call on the same line no longer swallows a real key.
    (tmp_path / "leak.py").write_text(
        'parts.append(x); real_key = "-----BEGIN RSA PRIVATE KEY-----"\n',
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path)
    findings = HardcodedPrivateKeyInSourceGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].severity == "critical"


def _unterminated_append_tree(tmp_path: Path, n: int) -> Path:
    # Issue #985's regex flaw, with the reachable shape corrected against the REAL call site
    # (`_ANTI_PATTERN.search(line[: m.start()])` in `_line_marker`), not the issue's own
    # synthetic benchmark string. A whitespace run immediately followed by the PEM header (no
    # trailing non-whitespace) matches on the FIRST attempt regardless of the old pattern's flaw
    # — no backtracking needed, so that exact shape is fast even pre-fix (verified directly: same
    # sub-millisecond time old vs. new). The old `\s*["']?\s*$` is only forced into exhaustive
    # backtracking when the prefix must FAIL to match: one extra non-whitespace, non-quote
    # character (`Y` below) between the whitespace run and the header does that — verified
    # 9.6s at n=32000 pre-fix vs. 0.011s post-fix on this exact shape.
    root = tmp_path / f"n{n}"
    root.mkdir()
    (root / "leak.py").write_text(
        "x.append(" + " " * n + "Y-----BEGIN RSA PRIVATE KEY-----\n", encoding="utf-8"
    )
    return root


@pytest.mark.slow
def test_hardcoded_private_key_in_source_unterminated_append_whitespace_stays_linear(
    tmp_path: Path,
) -> None:
    sizes = [500, 2000, 8000, 32000]
    roots = {n: _unterminated_append_tree(tmp_path, n) for n in sizes}
    guard = HardcodedPrivateKeyInSourceGuard()

    def scan(n: int) -> None:
        guard.run(roots[n], mkprofile(roots[n]))

    assert_growth(scan, sizes, expected="linear")


def test_hardcoded_private_key_in_source_fires_on_pgp_block_header(tmp_path: Path) -> None:
    # Regression (PR #479 review): PGP armor is `-----BEGIN PGP PRIVATE KEY BLOCK-----` — the word
    # BLOCK sits between `PRIVATE KEY` and the closing `-----`. The closing-delimiter requirement
    # (§E.1) must still match this real committed-key form, not just the RSA/EC/OPENSSH shapes.
    (tmp_path / "key.asc").write_text(
        "-----BEGIN PGP PRIVATE KEY BLOCK-----\n"
        "lQVYBGABCDEFAKCDEFrealpgpkeymaterialbase64lines1234567890abcdef\n"
        "-----END PGP PRIVATE KEY BLOCK-----\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path)
    findings = HardcodedPrivateKeyInSourceGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].severity == "critical"


def test_hardcoded_private_key_in_source_silent_on_prose_header_without_closing_dashes(
    tmp_path: Path,
) -> None:
    # FP-bait (§E.1): an instructional doc that quotes the PEM header LABEL in prose without the
    # closing `-----` delimiter is not committed key material — a mere doc mention must never yield
    # a critical. This produced a critical FP on a deploy guide (and recurred on 4 targets).
    (tmp_path / "cloud-deploy.md").write_text(
        "## Add your deploy key\n\n"
        "Copy the entire content including the `-----BEGIN OPENSSH PRIVATE KEY` header line, then\n"
        "paste it into the server's ~/.ssh directory.\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path)
    assert HardcodedPrivateKeyInSourceGuard().run(tmp_path, profile) == []


def test_hardcoded_private_key_in_source_silent_on_same_line_begin_and_end_prose_mention(
    tmp_path: Path,
) -> None:
    # FP found scanning a real deployment guide (dynamous-community/ai-agent-mastery):
    # both complete headers named in one sentence, closing dashes on both, no key body at all —
    # §E.1 alone doesn't exclude this since the closing dashes ARE present. The space between the
    # two quoted headers ("... and ...") is what marks this as prose, not embedded key material.
    (tmp_path / "cloud-deploy.md").write_text(
        "**Important:** Copy the entire content including the "
        "`-----BEGIN OPENSSH PRIVATE KEY-----` and `-----END OPENSSH PRIVATE KEY-----` lines.\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path)
    assert HardcodedPrivateKeyInSourceGuard().run(tmp_path, profile) == []


def test_hardcoded_private_key_in_source_fires_on_single_line_escaped_real_key(
    tmp_path: Path,
) -> None:
    # The direction traded against (CLAUDE.md Rule 1): a real key committed as a single-line,
    # `\n`-escaped value (the common .env/JSON shape) also has BEGIN and END on one physical line —
    # it must still fire. No literal space appears between the markers here, only base64 and `\n`
    # escapes, which is exactly what distinguishes it from the prose case above.
    (tmp_path / ".env").write_text(
        'PRIVATE_KEY="-----BEGIN RSA PRIVATE KEY-----\\n'
        'MIIEpAIBAAKCAQEA1234567890placeholderkeymaterial1234567890abcdef\\n'
        '-----END RSA PRIVATE KEY-----\\n"\n',
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path)
    findings = HardcodedPrivateKeyInSourceGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].severity == "critical"


def test_hardcoded_private_key_in_source_fires_on_space_flattened_real_key(
    tmp_path: Path,
) -> None:
    # Round-3 fix (PR #728 review): the original "any space between the markers" discriminator
    # silently suppressed this shape — a real key whose embedded newlines were flattened to literal
    # spaces (a copy-paste-into-single-line-field or `tr '\n' ' '` reflow), a real and unexotic way
    # single-line key material gets produced. It must still fire.
    (tmp_path / "flattened.txt").write_text(
        "-----BEGIN RSA PRIVATE KEY----- "
        "MIIEpAIBAAKCAQEA1234567890placeholderkeymaterial1234567890abcdef "
        "-----END RSA PRIVATE KEY-----\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path)
    findings = HardcodedPrivateKeyInSourceGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].severity == "critical"


def test_hardcoded_private_key_in_source_fires_on_one_stray_space_in_escaped_key(
    tmp_path: Path,
) -> None:
    # Same round-3 regression, narrower shape: an otherwise `\n`-escaped key with a single
    # accidental space somewhere in the base64 body. The old discriminator went silent on any
    # space at all; the new one only cares whether a long base64 run still exists either side of
    # it — realistic here means the body is long enough (as any real RSA/EC key's is) that one
    # stray space still leaves a 40+-char run on at least one side.
    (tmp_path / ".env").write_text(
        'PRIVATE_KEY="-----BEGIN RSA PRIVATE KEY-----\\n'
        'MIIEpAIBAAKCAQEA '
        '1234567890abcdefghij1234567890abcdefghij1234567890abcdefghij\\n'
        '-----END RSA PRIVATE KEY-----\\n"\n',
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path)
    findings = HardcodedPrivateKeyInSourceGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].severity == "critical"


def test_hardcoded_private_key_in_source_applies_unconditionally(tmp_path: Path) -> None:
    profile = mkprofile(tmp_path, features=set())
    assert HardcodedPrivateKeyInSourceGuard().applies(profile) is True


# --- the PEM label space (#575) ------------------------------------------------------------------
# The guard used to match an ENUMERATED key-type token, and the enumeration shipped two false
# negatives on a CRITICAL guard: PGP armor (PR #479) and then `ENCRYPTED`/`ANY`/`SM2` at once (#575).
# The fix was to match the `PRIVATE KEY` marker itself, and the point of THESE tables is that the
# next label the world defines fails a test instead of silently passing an audit. One row per label.
#
# Source of the list: `PEM_STRING_*` in openssl/pem.h (RSA, DSA, EC, PKCS8INF, PKCS8, EVP_PKEY,
# SM2PRIVATEKEY), plus the OpenSSH proprietary format and RFC 4880 armor. Verified against real
# `openssl`/`ssh-keygen` output during the #575 investigation: `openssl pkcs8 -topk8 -v2 aes-256-cbc`
# emits `ENCRYPTED PRIVATE KEY` for RSA, EC and Ed25519 alike, and so does `ssh-keygen -m PKCS8`.

_PRIVATE_KEY_LABELS = [
    "RSA PRIVATE KEY",              # PEM_STRING_RSA          (PKCS#1, openssl -traditional)
    "DSA PRIVATE KEY",              # PEM_STRING_DSA
    "EC PRIVATE KEY",               # PEM_STRING_ECPRIVATEKEY (SEC1, openssl ecparam -genkey)
    "PRIVATE KEY",                  # PEM_STRING_PKCS8INF     (PKCS#8 plain, openssl genpkey)
    "ENCRYPTED PRIVATE KEY",        # PEM_STRING_PKCS8        (PKCS#8 encrypted -- the #575 miss)
    "ANY PRIVATE KEY",              # PEM_STRING_EVP_PKEY     (also missed pre-#575)
    "SM2 PRIVATE KEY",              # PEM_STRING_SM2PRIVATEKEY(also missed pre-#575)
    "OPENSSH PRIVATE KEY",          # openssh proprietary     (ssh-keygen default)
    "PGP PRIVATE KEY BLOCK",        # RFC 4880 armor          (the PR #479 miss)
]

# The PUBLIC half of the same header space. A public key is not key material to rotate, and the
# widening in #575 must not have swallowed it: this is the direction traded against (CLAUDE.md Rule 1).
_NOT_PRIVATE_KEY_LABELS = [
    "PUBLIC KEY",                   # PEM_STRING_PUBLIC
    "RSA PUBLIC KEY",               # PEM_STRING_RSA_PUBLIC
    "DSA PUBLIC KEY",               # PEM_STRING_DSA_PUBLIC
    "ECDSA PUBLIC KEY",             # PEM_STRING_ECDSA_PUBLIC
    "PGP PUBLIC KEY BLOCK",         # RFC 4880 armor, public half
    "CERTIFICATE",                  # PEM_STRING_X509
    "CERTIFICATE REQUEST",          # PEM_STRING_X509_REQ
    "DH PARAMETERS",                # PEM_STRING_DHPARAMS -- parameters, not key material
]


@pytest.mark.parametrize("label", _PRIVATE_KEY_LABELS)
def test_hardcoded_private_key_in_source_fires_on_every_pem_private_key_label(
    tmp_path: Path, label: str
) -> None:
    (tmp_path / "key.pem").write_text(
        f"-----BEGIN {label}-----\n"
        "MIIEpAIBAAKCAQEA1234567890placeholderkeymaterial1234567890abcdef\n"
        f"-----END {label}-----\n",
        encoding="utf-8",
    )
    findings = HardcodedPrivateKeyInSourceGuard().run(tmp_path, mkprofile(tmp_path))
    assert len(findings) == 1, f"{label} is a real private-key label and must fire"
    assert findings[0].severity == "critical"
    assert findings[0].location == "key.pem:1"


@pytest.mark.parametrize("label", _NOT_PRIVATE_KEY_LABELS)
def test_hardcoded_private_key_in_source_silent_on_non_private_key_pem_labels(
    tmp_path: Path, label: str
) -> None:
    # FP-bait for the #575 widening: a public key / certificate / parameter block is a complete,
    # five-dash PEM header in the same syntactic shape, and none of it is committed key material.
    (tmp_path / "public.pem").write_text(
        f"-----BEGIN {label}-----\n"
        "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEplaceholder1234567890abcdef\n"
        f"-----END {label}-----\n",
        encoding="utf-8",
    )
    assert HardcodedPrivateKeyInSourceGuard().run(tmp_path, mkprofile(tmp_path)) == []


def test_hardcoded_private_key_in_source_fires_on_real_encrypted_pkcs8_block(
    tmp_path: Path,
) -> None:
    # The reported #575 case end to end, in the shape `openssl pkcs8 -topk8 -v2 aes-256-cbc` writes:
    # a committed, passphrase-protected key. Encrypted is not safe -- the passphrase is usually in
    # the same repo or the same deployment, and git history keeps the key after the file is deleted.
    (tmp_path / "server.pem").write_text(
        "-----BEGIN ENCRYPTED PRIVATE KEY-----\n"
        "MIIFNTBfBgkqhkiG9w0BBQ0wUjAxBgkqhkiG9w0BBQwwJAQQ4LPM94IV2Zqg/2O1\n"
        "XBj4OwICCAAwDAYIKoZIhvcNAgkFADAdBglghkgBZQMEASoEEKY1TA9udziIK8Kb\n"
        "-----END ENCRYPTED PRIVATE KEY-----\n",
        encoding="utf-8",
    )
    findings = HardcodedPrivateKeyInSourceGuard().run(tmp_path, mkprofile(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "hardcoded-private-key-in-source/pem-header-literal"
    assert findings[0].severity == "critical"
    assert findings[0].location == "server.pem:1"


# --- the same three FP-bait shapes, re-aimed at the newly-admitted labels (#575) ------------------
# CLAUDE.md Rule 1: a widening carries FP-bait proving the benign neighbour stays silent. Each of
# these already had an RSA-shaped test above; a label the guard could not match before was trivially
# "silent" for the wrong reason, so the suppressors were never exercised against it at all.


def test_hardcoded_private_key_in_source_silent_on_encrypted_prose_without_closing_dashes(
    tmp_path: Path,
) -> None:
    # §E.1, aimed at ENCRYPTED: a deploy guide quoting the label without the closing `-----`.
    (tmp_path / "deploy.md").write_text(
        "## Upload your key\n\n"
        "Copy everything after `-----BEGIN ENCRYPTED PRIVATE KEY` and paste it into the form.\n",
        encoding="utf-8",
    )
    assert HardcodedPrivateKeyInSourceGuard().run(tmp_path, mkprofile(tmp_path)) == []


def test_hardcoded_private_key_in_source_silent_on_encrypted_runtime_built_string(
    tmp_path: Path,
) -> None:
    # The `.append(` anti-pattern, aimed at ENCRYPTED: a PEM-generating utility emitting a header
    # it is creating, not embedding.
    (tmp_path / "gen_key.py").write_text(
        'buf.append("-----BEGIN ENCRYPTED PRIVATE KEY-----\\n")\n', encoding="utf-8"
    )
    assert HardcodedPrivateKeyInSourceGuard().run(tmp_path, mkprofile(tmp_path)) == []


def test_hardcoded_private_key_in_source_pragma_silences_encrypted(tmp_path: Path) -> None:
    # The pragma must reach a newly-admitted label too -- an opt-out that only works for the labels
    # the guard already matched would be an opt-out the user cannot rely on (CLAUDE.md Rule 4).
    (tmp_path / "decoy.py").write_text(
        "K = '-----BEGIN ENCRYPTED PRIVATE KEY-----'  # security: allow-hardcoded-private-key\n",
        encoding="utf-8",
    )
    assert HardcodedPrivateKeyInSourceGuard().run(tmp_path, mkprofile(tmp_path)) == []


# --- the fabricated-label axis of the #575 widening: DELIBERATE, pinned here ----------------------
# Matching the `PRIVATE KEY` marker instead of a vetted label list means a made-up label inside a
# complete five-dash header also fires. That is a real widening of the false-positive surface and it
# was accepted on purpose (PR #706 review, M2), so it is pinned rather than left as an unexamined
# side effect: if someone later narrows the class, these rows fail and force the trade-off back into
# the open instead of letting it change silently.
#
# Why accepted rather than narrowed. The alternative is a denylist of placeholder words, which
# reintroduces exactly the hand-maintained list that #575 existed to remove, one layer over — and it
# would be strictly worse than the old list, because a denylist can SUPPRESS a real committed key
# whose label happens to contain one of those words, where the old allowlist only ever missed one.
# Two measured facts bound the cost:
#   1. This widens an EXISTING false-positive class rather than opening a new one. A doc that pastes
#      a complete `-----BEGIN RSA PRIVATE KEY-----` placeholder with the closing dashes already
#      fires on the pre-#575 guard; §E.1 only ever excused the no-closing-dashes prose mention.
#   2. The pragma reaches these labels (asserted below), so the user's opt-out is intact. A
#      suppression the user cannot reach would be strictly worse than the FP (CLAUDE.md Rule 4).

_FABRICATED_LABELS = ["EXAMPLE", "TEST", "FAKE", "SAMPLE", "YOUR", "REDACTED"]


@pytest.mark.parametrize("label", _FABRICATED_LABELS)
def test_hardcoded_private_key_in_source_fires_on_fabricated_label_by_design(
    tmp_path: Path, label: str
) -> None:
    # NOT an FP-bait test: these are asserted to FIRE, and that is the accepted behaviour.
    (tmp_path / "notes.md").write_text(
        f"-----BEGIN {label} PRIVATE KEY-----\n", encoding="utf-8"
    )
    findings = HardcodedPrivateKeyInSourceGuard().run(tmp_path, mkprofile(tmp_path))
    assert len(findings) == 1, (
        f"{label} is not a real PEM label, but a complete five-dash header carrying it is flagged "
        "by design -- see the comment above before changing this"
    )


@pytest.mark.parametrize("label", _FABRICATED_LABELS)
def test_hardcoded_private_key_in_source_pragma_reaches_a_fabricated_label(
    tmp_path: Path, label: str
) -> None:
    # The escape hatch for the row above. This is what keeps the accepted FP from being a
    # suppression the user cannot reach (CLAUDE.md Rule 4).
    (tmp_path / "notes.py").write_text(
        f"K = '-----BEGIN {label} PRIVATE KEY-----'  # security: allow-hardcoded-private-key\n",
        encoding="utf-8",
    )
    assert HardcodedPrivateKeyInSourceGuard().run(tmp_path, mkprofile(tmp_path)) == []


# --- bounded reads (#443) ------------------------------------------------------------------------
# The walk is unfiltered, so a committed multi-GB model checkpoint used to be decoded whole (about 7x
# its size in memory) just to learn it had no PEM marker; at the out-of-memory tail that errored the
# guard and discarded every CRITICAL it had already collected. A file over 1 MiB now takes a second
# read path (a whole-file byte pre-filter, then a line stream), so these tests pin that path to the
# first one: every fire and every FP-bait case below gives the same result on either side of the cap.
# They write raw bytes, never write_text(), so the line endings under test are exactly the ones
# written, on Windows too.

_CAP = _hpk._FULL_READ_MAX_BYTES
_RULE = "hardcoded-private-key-in-source/pem-header-literal"


@pytest.fixture
def no_full_read_over_cap(monkeypatch: pytest.MonkeyPatch) -> None:
    """Fail the test if the guard ever reads a file over the cap whole."""
    real_read = _hpk.read

    def spy(p: Path) -> str:
        assert p.stat().st_size <= _CAP, f"whole-file read of {p.name} ({p.stat().st_size} bytes)"
        return real_read(p)

    monkeypatch.setattr(_hpk, "read", spy)


def _padding(nl: str, size: int = _CAP + (1 << 20)) -> str:
    line = "# " + "z" * 97 + nl
    return line * (size // len(line) + 1)


def _run(root: Path) -> list[tuple[str, str]]:
    findings = HardcodedPrivateKeyInSourceGuard().run(root, mkprofile(root, features=set()))
    return sorted((f.location, f.rule or "") for f in findings)


@pytest.mark.usefixtures("no_full_read_over_cap")
def test_large_binary_without_marker_is_never_read_whole(tmp_path: Path) -> None:
    (tmp_path / "models").mkdir()
    (tmp_path / "models" / "weights.bin").write_bytes(os.urandom(8 << 20))
    tracemalloc.start()
    try:
        assert _run(tmp_path) == []
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    # Reading it whole peaked at about 7x the file (56 MiB here); the byte pre-filter is ~2 chunks.
    assert peak < 8 << 20, peak


@pytest.mark.usefixtures("no_full_read_over_cap")
def test_large_sparse_file_without_marker_is_silent(tmp_path: Path) -> None:
    blob = tmp_path / "data.parquet"
    blob.write_bytes(b"PAR1")
    os.truncate(blob, 64 << 20)  # sparse: a 64 MiB st_size without a real 64 MiB write
    assert _run(tmp_path) == []


@pytest.mark.usefixtures("no_full_read_over_cap")
def test_key_past_the_head_of_a_large_file_fires_on_its_line(tmp_path: Path) -> None:
    # The direction traded against (Rule 1): nothing is head-truncated, so a key after 2 MiB of
    # dataset still fires as CRITICAL, on the right line.
    pad = _padding("\n")
    key = "-----BEGIN RSA PRIVATE KEY-----\nMIIEow\n-----END RSA PRIVATE KEY-----\n"
    (tmp_path / "dump.jsonl").write_bytes((pad + key).encode())
    assert _run(tmp_path) == [(f"dump.jsonl:{pad.count(chr(10)) + 1}", _RULE)]


@pytest.mark.usefixtures("no_full_read_over_cap")
@pytest.mark.parametrize("offset", [1, 5, 9])
def test_marker_straddling_the_pre_filter_chunk_boundary_fires(tmp_path: Path, offset: int) -> None:
    # The marker starts `offset` bytes before the pre-filter's first 1 MiB chunk edge.
    head_len = (1 << 20) - offset
    head = ("y" * 99 + "\n") * (head_len // 100)
    head += "y" * (head_len - len(head) - 1) + "\n"
    assert len(head) == head_len
    body = "-----BEGIN OPENSSH PRIVATE KEY-----\n" + "q" * 64 + "\n"
    (tmp_path / "bundle.txt").write_bytes((head + body).encode())
    assert (tmp_path / "bundle.txt").stat().st_size > _CAP
    assert _run(tmp_path) == [(f"bundle.txt:{head.count(chr(10)) + 1}", _RULE)]


_PARITY_CASES = {
    "rsa_block": (
        "KEY = '''-----BEGIN RSA PRIVATE KEY-----\n"
        "MIIEowIBAAKCAQEA1c7\n"
        "-----END RSA PRIVATE KEY-----'''\n"
    ),
    "openssh_env": "SSH_KEY=-----BEGIN OPENSSH PRIVATE KEY-----\n",
    "bare_pkcs8": (
        "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQ\n-----END PRIVATE KEY-----\n"
    ),
    "pgp_block": (
        "-----BEGIN PGP PRIVATE KEY BLOCK-----\nlQVYBGABCDEF\n-----END PGP PRIVATE KEY BLOCK-----\n"
    ),
    "commented_out": "# old deploy key:\n# -----BEGIN RSA PRIVATE KEY-----\n# MIIEowIBAAKCAQEA...\n",
    "trailing_url": (
        "PRIV = '-----BEGIN RSA PRIVATE KEY-----'  # rotate via https://vault.example.com\n"
    ),
    "trailing_c_comment": "-----BEGIN OPENSSH PRIVATE KEY----- // deploy key\n",
    "earlier_append": 'parts.append(x); real_key = "-----BEGIN RSA PRIVATE KEY-----"\n',
    "escaped_single_line": (
        'PRIVATE_KEY="-----BEGIN RSA PRIVATE KEY-----\\n'
        "MIIEpAIBAAKCAQEA1234567890placeholderkeymaterial1234567890abcdef\\n"
        '-----END RSA PRIVATE KEY-----\\n"\n'
    ),
    "space_flattened": (
        "-----BEGIN RSA PRIVATE KEY----- "
        "MIIEpAIBAAKCAQEA1234567890placeholderkeymaterial1234567890abcdef "
        "-----END RSA PRIVATE KEY-----\n"
    ),
    # FP-bait: each must stay silent on the large-file path too.
    "prose_no_closing_dashes": (
        "Copy the content including the `-----BEGIN OPENSSH PRIVATE KEY` header.\n"
    ),
    "prose_begin_and_end": (
        "Copy the `-----BEGIN OPENSSH PRIVATE KEY-----` and "
        "`-----END OPENSSH PRIVATE KEY-----` lines.\n"
    ),
    "runtime_append": 'buf.append("-----BEGIN RSA PRIVATE KEY-----\\n")\n',
    "public_key": "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0B\n-----END PUBLIC KEY-----\n",
    "pragma": "KEY = '-----BEGIN RSA PRIVATE KEY-----'  # security: allow-hardcoded-private-key\n",
}


@pytest.mark.usefixtures("no_full_read_over_cap")
@pytest.mark.parametrize("nl", ["\n", "\r\n", "\r"], ids=["lf", "crlf", "cr"])
@pytest.mark.parametrize("case", sorted(_PARITY_CASES))
def test_large_file_path_matches_small_file_path(tmp_path: Path, case: str, nl: str) -> None:
    # Parity (Rules 1 and 4): the same content gives the same findings, with line numbers shifted
    # by exactly the padding, whether it is read whole or streamed. Covers the pragma, the
    # anti-pattern, same-line prose, and CRLF / bare-CR endings.
    content = _PARITY_CASES[case].replace("\n", nl)
    small, large = tmp_path / "small", tmp_path / "large"
    small.mkdir()
    large.mkdir()
    (small / "f.txt").write_bytes(content.encode())
    pad = _padding(nl)
    (large / "f.txt").write_bytes((pad + content).encode())
    assert (large / "f.txt").stat().st_size > _CAP
    shift = len(pad.splitlines())
    expected = [(f"f.txt:{int(loc.split(':')[1]) + shift}", rule) for loc, rule in _run(small)]
    assert _run(large) == expected


@pytest.mark.usefixtures("no_full_read_over_cap")
def test_overlong_single_line_with_escaped_key_fires(tmp_path: Path) -> None:
    # A minified JSON blob: one line far over the line cap, with a `\n`-escaped key in the middle.
    filler = '{"k":"' + "v" * (3 << 20) + '"}'
    key = (
        '"PRIVATE_KEY":"-----BEGIN RSA PRIVATE KEY-----\\n'
        "MIIEpAIBAAKCAQEA1234567890placeholderkeymaterial1234567890abcdef\\n"
        '-----END RSA PRIVATE KEY-----\\n"'
    )
    (tmp_path / "bundle.min.json").write_bytes((filler + "," + key + "," + filler + "\n").encode())
    assert _run(tmp_path) == [("bundle.min.json:1", _RULE)]


@pytest.mark.usefixtures("no_full_read_over_cap")
def test_pragma_far_from_header_on_one_overlong_line_still_silences(tmp_path: Path) -> None:
    # Rule 4: a pragma the user wrote must not stop working on the large-file path, even when the
    # line is so long that the header and the pragma land in different pieces of it.
    line = (
        "KEY = '-----BEGIN RSA PRIVATE KEY-----' + '" + "x" * (3 << 20) + "'"
        "  # security: allow-hardcoded-private-key\n"
    )
    (tmp_path / "decoy.py").write_bytes(line.encode())
    assert _run(tmp_path) == []
    # ...and the same line without the pragma fires, so the silence above is the pragma's doing.
    (tmp_path / "decoy.py").write_bytes(line.replace("# security: allow", "# note:").encode())
    assert len(_run(tmp_path)) == 1


@pytest.mark.usefixtures("no_full_read_over_cap")
@pytest.mark.parametrize("cut", [1, 10, 20, 30, 34])
def test_header_cut_by_a_piece_boundary_of_an_overlong_line_fires_once(tmp_path: Path, cut: int) -> None:
    # The line-overlap edge (#959 review). A header that starts `cut` characters before the first
    # piece of an overlong line ends is split by the piece boundary for every `cut` below its
    # length (31); the overlap must carry it whole into the next piece, or the boundary hides a
    # real key. `cut=10` leaves exactly `-----BEGIN` in the first piece, the pre-filter literal
    # without the header, and `cut=34` is the control where the header fits before the boundary.
    # Exactly ONE finding either way: the whole header seen again in the overlap is the same
    # header, not a second one.
    header = "-----BEGIN RSA PRIVATE KEY-----"
    assert len(header) + cut < _hpk._LINE_OVERLAP_CHARS
    line = "x" * (_hpk._MAX_LINE_CHARS - cut) + header + "\\nMIIEpAIBAAKCAQEA" + "y" * 200 + "\n"
    (tmp_path / "blob.txt").write_bytes(line.encode())
    assert (tmp_path / "blob.txt").stat().st_size > _CAP
    assert _run(tmp_path) == [("blob.txt:1", _RULE)]
