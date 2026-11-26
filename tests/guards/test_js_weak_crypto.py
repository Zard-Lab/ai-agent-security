from __future__ import annotations

import pytest

from agentsec.guards.js_weak_crypto import JsWeakCryptoGuard
from tests.guards._common import *  # noqa: F401,F403

# --- crypto.createHash -----------------------------------------------------------------------

def test_flags_create_hash_md5(tmp_path: Path) -> None:
    (tmp_path / "h.js").write_text(
        "const crypto = require('crypto');\n"
        "const digest = crypto.createHash('md5').update(data).digest('hex');\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"javascript"})
    findings = JsWeakCryptoGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "js-weak-crypto/weak-hash-algorithm"
    assert findings[0].severity == "high"


def test_silent_on_create_hash_sha256(tmp_path: Path) -> None:
    # FP-bait: the safe/strong hash must not fire.
    (tmp_path / "h.js").write_text(
        "const crypto = require('crypto');\n"
        "const digest = crypto.createHash('sha256').update(data).digest('hex');\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"javascript"})
    assert JsWeakCryptoGuard().run(tmp_path, profile) == []


# --- crypto.createCipher / createDecipher (deprecated function, any algorithm) -----------------

def test_flags_create_cipher_any_algorithm(tmp_path: Path) -> None:
    (tmp_path / "c.js").write_text(
        "const crypto = require('crypto');\n"
        "const cipher = crypto.createCipher('aes-256-cbc', key);\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"javascript"})
    findings = JsWeakCryptoGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "js-weak-crypto/deprecated-cipher-function"


def test_flags_create_decipher(tmp_path: Path) -> None:
    (tmp_path / "c.js").write_text(
        "const decipher = crypto.createDecipher('aes-256-cbc', key);\n", encoding="utf-8"
    )
    profile = mkprofile(tmp_path, features={"javascript"})
    findings = JsWeakCryptoGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "js-weak-crypto/deprecated-cipher-function"


def test_silent_on_create_cipheriv_safe_replacement(tmp_path: Path) -> None:
    # regex-precision FP-bait: createCipheriv is the SAFE modern replacement function — merely
    # containing the substring "Cipher" must not trip the createCipher (deprecated-function) rule.
    (tmp_path / "c.js").write_text(
        "const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);\n", encoding="utf-8"
    )
    profile = mkprofile(tmp_path, features={"javascript"})
    assert JsWeakCryptoGuard().run(tmp_path, profile) == []


# --- crypto.createCipheriv / createDecipheriv with a weak algorithm string ---------------------

def test_flags_create_cipheriv_weak_algorithm(tmp_path: Path) -> None:
    (tmp_path / "c.js").write_text(
        "const cipher = crypto.createCipheriv('des-ede3', key, iv);\n", encoding="utf-8"
    )
    profile = mkprofile(tmp_path, features={"javascript"})
    findings = JsWeakCryptoGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "js-weak-crypto/weak-cipher-algorithm"


def test_flags_create_decipheriv_rc4(tmp_path: Path) -> None:
    (tmp_path / "c.js").write_text(
        "const decipher = crypto.createDecipheriv('rc4', key, iv);\n", encoding="utf-8"
    )
    profile = mkprofile(tmp_path, features={"javascript"})
    findings = JsWeakCryptoGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "js-weak-crypto/weak-cipher-algorithm"


def test_silent_on_create_cipheriv_strong_algorithm(tmp_path: Path) -> None:
    (tmp_path / "c.js").write_text(
        "const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);\n", encoding="utf-8"
    )
    profile = mkprofile(tmp_path, features={"javascript"})
    assert JsWeakCryptoGuard().run(tmp_path, profile) == []


# --- CryptoJS ------------------------------------------------------------------------------

def test_flags_cryptojs_md5(tmp_path: Path) -> None:
    (tmp_path / "c.js").write_text(
        "import CryptoJS from 'crypto-js';\n"
        "const hash = CryptoJS.MD5(data).toString();\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"javascript"})
    findings = JsWeakCryptoGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "js-weak-crypto/weak-hash-algorithm"


def test_silent_on_cryptojs_sha256(tmp_path: Path) -> None:
    (tmp_path / "c.js").write_text(
        "import CryptoJS from 'crypto-js';\n"
        "const hash = CryptoJS.SHA256(data).toString();\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"javascript"})
    assert JsWeakCryptoGuard().run(tmp_path, profile) == []


def test_flags_cryptojs_des_encrypt(tmp_path: Path) -> None:
    (tmp_path / "c.js").write_text(
        "const ct = CryptoJS.DES.encrypt(message, key).toString();\n", encoding="utf-8"
    )
    profile = mkprofile(tmp_path, features={"javascript"})
    findings = JsWeakCryptoGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "js-weak-crypto/weak-cipher-algorithm"


def test_flags_cryptojs_rc4_encrypt(tmp_path: Path) -> None:
    (tmp_path / "c.js").write_text(
        "const ct = CryptoJS.RC4.encrypt(message, key).toString();\n", encoding="utf-8"
    )
    profile = mkprofile(tmp_path, features={"javascript"})
    findings = JsWeakCryptoGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "js-weak-crypto/weak-cipher-algorithm"


def test_silent_on_cryptojs_aes_encrypt(tmp_path: Path) -> None:
    (tmp_path / "c.js").write_text(
        "const ct = CryptoJS.AES.encrypt(message, key).toString();\n", encoding="utf-8"
    )
    profile = mkprofile(tmp_path, features={"javascript"})
    assert JsWeakCryptoGuard().run(tmp_path, profile) == []


# --- pragma / applies / comment / non-product path ----------------------------------------------

def test_pragma_suppresses(tmp_path: Path) -> None:
    (tmp_path / "h.js").write_text(
        "const digest = crypto.createHash('md5').update(data).digest('hex');  "
        "// security: allow-js-weak-crypto\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"javascript"})
    assert JsWeakCryptoGuard().run(tmp_path, profile) == []


def test_pragma_does_not_suppress_other_lines_in_the_file(tmp_path: Path) -> None:
    # Regression (#548 gate review, Critical 1): the pragma must silence only the line it is
    # on, not the whole file. A pragma'd MD5 hash must not hide an unrelated SHA-1 hash below it.
    (tmp_path / "h.js").write_text(
        "const a = crypto.createHash('md5').update(data).digest('hex');  "
        "// security: allow-js-weak-crypto\n"
        "const b = crypto.createHash('sha1').update(other).digest('hex');\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"javascript"})
    findings = JsWeakCryptoGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].location.endswith(":2")


def test_silent_on_comment_mentioning_pattern(tmp_path: Path) -> None:
    (tmp_path / "notes.js").write_text(
        "// Never do: crypto.createHash('md5')\n"
        "const digest = crypto.createHash('sha256').update(data).digest('hex');\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"javascript"})
    assert JsWeakCryptoGuard().run(tmp_path, profile) == []


def test_not_applies_without_js_or_ts(tmp_path: Path) -> None:
    profile = mkprofile(tmp_path, features=set())
    assert not JsWeakCryptoGuard().applies(profile)


def test_applies_with_typescript(tmp_path: Path) -> None:
    profile = mkprofile(tmp_path, features={"typescript"})
    assert JsWeakCryptoGuard().applies(profile)


def test_nonproduct_path_skipped(tmp_path: Path) -> None:
    d = tmp_path / "examples"
    d.mkdir(parents=True)
    (d / "demo.js").write_text(
        "const digest = crypto.createHash('md5').update(data).digest('hex');\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"javascript"})
    assert JsWeakCryptoGuard().run(tmp_path, profile) == []


# --- adversarial self-test findings, pinned as tests ---------------------------------------

def test_silent_on_create_hmac_sha1(tmp_path: Path) -> None:
    # Deliberate scope decision, mirroring weak_crypto.py's Python-side scope: HMAC-SHA1 is not
    # the same weak-algorithm class as bare SHA-1 hashing (HMAC remains collision-resistant even
    # with a broken underlying hash), so createHmac is never flagged, regardless of digest.
    (tmp_path / "h.js").write_text(
        "const mac = crypto.createHmac('sha1', key).update(data).digest('hex');\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"javascript"})
    assert JsWeakCryptoGuard().run(tmp_path, profile) == []


def test_known_bypass_algorithm_via_variable_not_flagged(tmp_path: Path) -> None:
    # Known bypass (documented in the design doc): the algorithm name passed via a variable,
    # not a string literal directly in the call, is invisible to this name-based, single-line
    # regex — the same precision/recall trade-off `weak_crypto.py` already accepts elsewhere
    # (e.g. its own "Indirection" known bypass for insecure-random-secret).
    (tmp_path / "h.js").write_text(
        "const algo = 'md5';\ncrypto.createHash(algo);\n", encoding="utf-8"
    )
    profile = mkprofile(tmp_path, features={"javascript"})
    assert JsWeakCryptoGuard().run(tmp_path, profile) == []


def test_pragma_quoted_in_a_string_on_the_line_does_not_suppress(tmp_path: Path) -> None:
    # #424 E4: the per-line check reads the same-length comment-only view, so a string literal on
    # the finding's own line that quotes the pragma is content - only a real `//` comment opts out.
    (tmp_path / "h.js").write_text(
        "const digest = crypto.createHash('md5').update(data).digest('hex'); "
        'const doc = "add // security: allow-js-weak-crypto";\n',
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"javascript"})
    assert len(JsWeakCryptoGuard().run(tmp_path, profile)) == 1


# --- ECB and legacy cipher names (mined from eslint-plugin-security-rules' banned-algorithm list) ---


def _cipher_findings(tmp_path: Path, body: str) -> list[tuple[str, str]]:
    (tmp_path / "enc.js").write_text("const crypto = require('crypto');\n" + body, encoding="utf-8")
    profile = mkprofile(tmp_path, features={"javascript"})
    return [(f.rule, f.severity) for f in JsWeakCryptoGuard().run(tmp_path, profile)]


@pytest.mark.parametrize(
    "body",
    [
        "crypto.createCipheriv('aes-256-ecb', key, null);\n",
        'crypto.createDecipheriv("AES-128-ECB", key, null);\n',
        "const { createCipheriv } = require('crypto');\ncreateCipheriv('camellia-128-ecb', k, null);\n",
        "const c = require('crypto');\nc.createCipheriv('bf-ecb', k, null);\n",
        "const enc = CryptoJS.AES.encrypt(m, k, { mode: CryptoJS.mode.ECB });\n",
    ],
)
def test_ecb_mode_is_high(tmp_path: Path, body: str) -> None:
    assert _cipher_findings(tmp_path, body) == [("js-weak-crypto/ecb-cipher-mode", "high")]


@pytest.mark.parametrize(
    "name", ["bf-cbc", "des-ede3-cbc", "des-cbc", "des-ede-cbc", "rc4-hmac-md5", "rc2-40-cbc", "cast5-cbc", "desx-cbc"]
)
def test_legacy_cipher_family_is_medium(tmp_path: Path, name: str) -> None:
    body = f"crypto.createCipheriv('{name}', key, iv);\n"
    assert _cipher_findings(tmp_path, body) == [("js-weak-crypto/weak-cipher-algorithm", "medium")]


def test_exact_legacy_names_stay_high(tmp_path: Path) -> None:
    body = "crypto.createCipheriv('des-ede3', key, iv);\n"
    assert _cipher_findings(tmp_path, body) == [("js-weak-crypto/weak-cipher-algorithm", "high")]


@pytest.mark.parametrize(
    "body",
    [
        "crypto.createCipheriv('aes-256-gcm', key, iv);\n",
        "crypto.createCipheriv('aes-256-cbc', key, iv);\n",
        "crypto.createCipheriv('chacha20-poly1305', key, iv);\n",
        "crypto.createCipheriv('bfx-custom', key, iv);\n",
        "// crypto.createCipheriv('aes-256-ecb', key, null);\n",
        "const enc = CryptoJS.AES.encrypt(m, k, { mode: CryptoJS.mode.CBC });\n",
    ],
)
def test_strong_or_commented_ciphers_silent(tmp_path: Path, body: str) -> None:
    assert _cipher_findings(tmp_path, body) == []


def test_ecb_pragma_suppresses(tmp_path: Path) -> None:
    body = "crypto.createCipheriv('aes-256-ecb', key, null); // security: allow-js-weak-crypto\n"
    assert _cipher_findings(tmp_path, body) == []
