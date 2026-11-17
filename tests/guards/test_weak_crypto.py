from __future__ import annotations

from agentsec.guards.weak_crypto import WeakCryptoGuard
from tests.guards._common import *  # noqa: F401,F403


def test_weak_crypto_flags_md5(tmp_path: Path) -> None:
    (tmp_path / "h.py").write_text("import hashlib\ndef d(b):\n    return hashlib.md5(b).hexdigest()\n", encoding="utf-8")
    findings = WeakCryptoGuard().run(tmp_path, _pyprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "weak-crypto/insecure-hash"
    assert findings[0].severity == "high"
    # backlog #4: the remediation must surface the non-security escape hatch (usedforsecurity=False)
    # for content-dedup/cache/ETag uses, so the fix is discoverable without weakening detection.
    assert "usedforsecurity=False" in findings[0].remediation

def test_weak_crypto_flags_sha1_and_ecb(tmp_path: Path) -> None:
    (tmp_path / "a.py").write_text("import hashlib\nhashlib.sha1(x)\n", encoding="utf-8")
    (tmp_path / "b.py").write_text("from Crypto.Cipher import AES\nc = AES.new(k, AES.MODE_ECB)\n", encoding="utf-8")
    assert len(WeakCryptoGuard().run(tmp_path, _pyprof(tmp_path))) == 2

def test_weak_crypto_flags_insecure_random_secret(tmp_path: Path) -> None:
    (tmp_path / "t.py").write_text("import random\ntoken = random.choice(alphabet)\n", encoding="utf-8")
    findings = WeakCryptoGuard().run(tmp_path, _pyprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "weak-crypto/insecure-random-secret"

def test_weak_crypto_passes_usedforsecurity_false_and_safe_random(tmp_path: Path) -> None:
    # md5 declared non-security, and random for a non-secret name -> both clean
    (tmp_path / "t.py").write_text(
        "import hashlib, random\n"
        "key = hashlib.md5(b, usedforsecurity=False).hexdigest()\n"
        "colour = random.choice(colours)\n", encoding="utf-8"
    )
    assert WeakCryptoGuard().run(tmp_path, _pyprof(tmp_path)) == []

def test_weak_crypto_pragma_opt_out(tmp_path: Path) -> None:
    (tmp_path / "t.py").write_text(
        "import hashlib\ndef d(b):\n    return hashlib.md5(b).hexdigest()  # security: allow-weak-crypto\n", encoding="utf-8"
    )
    assert WeakCryptoGuard().run(tmp_path, _pyprof(tmp_path)) == []

def test_weak_crypto_na_without_python() -> None:
    assert WeakCryptoGuard().applies(mkprofile(Path("/tmp"), features={"frontend"})) is False

def test_weak_crypto_flags_pycryptodome_weak_rsa(tmp_path: Path) -> None:
    (tmp_path / "k.py").write_text(
        "from Crypto.PublicKey import RSA\nkey = RSA.generate(1024)\n", encoding="utf-8"
    )
    findings = WeakCryptoGuard().run(tmp_path, _pyprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "weak-crypto/weak-key-size"

def test_weak_crypto_flags_pycryptodome_weak_dsa(tmp_path: Path) -> None:
    (tmp_path / "k.py").write_text(
        "from Crypto.PublicKey import DSA\nkey = DSA.generate(1024)\n", encoding="utf-8"
    )
    findings = WeakCryptoGuard().run(tmp_path, _pyprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "weak-crypto/weak-key-size"

def test_weak_crypto_flags_cryptography_lib_weak_key_size(tmp_path: Path) -> None:
    (tmp_path / "k.py").write_text(
        "from cryptography.hazmat.primitives.asymmetric import rsa\n"
        "key = rsa.generate_private_key(public_exponent=65537, key_size=1024)\n", encoding="utf-8"
    )
    findings = WeakCryptoGuard().run(tmp_path, _pyprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "weak-crypto/weak-key-size"

def test_weak_crypto_flags_cryptography_lib_weak_key_size_with_nested_call_before_it(
    tmp_path: Path,
) -> None:
    # FN-bait (review #395 M finding): a nested call earlier in the arg list (backend=
    # default_backend()) previously closed the old `[^)]*` scan at ITS `)`, hiding a real
    # weak key_size that came after it.
    (tmp_path / "k.py").write_text(
        "from cryptography.hazmat.primitives.asymmetric import rsa\n"
        "from cryptography.hazmat.backends import default_backend\n"
        "key = rsa.generate_private_key(\n"
        "    backend=default_backend(), public_exponent=65537, key_size=1024\n"
        ")\n", encoding="utf-8"
    )
    findings = WeakCryptoGuard().run(tmp_path, _pyprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "weak-crypto/weak-key-size"

def test_weak_crypto_silent_on_strong_key_sizes(tmp_path: Path) -> None:
    (tmp_path / "k.py").write_text(
        "from Crypto.PublicKey import RSA\n"
        "from cryptography.hazmat.primitives.asymmetric import rsa\n"
        "key1 = RSA.generate(2048)\n"
        "key2 = rsa.generate_private_key(public_exponent=65537, key_size=4096)\n", encoding="utf-8"
    )
    assert WeakCryptoGuard().run(tmp_path, _pyprof(tmp_path)) == []

def test_weak_crypto_silent_on_unrelated_key_size_kwarg(tmp_path: Path) -> None:
    # FP-bait: a `key_size=` kwarg to a function that isn't generate_private_key must not fire.
    (tmp_path / "k.py").write_text("configure_cache(key_size=128)\n", encoding="utf-8")
    assert WeakCryptoGuard().run(tmp_path, _pyprof(tmp_path)) == []

def test_weak_crypto_pragma_on_key_size_line_suppresses(tmp_path: Path) -> None:
    # #395 M: the pragma may sit on the `key_size=` line of a multi-line call, not the
    # `generate_private_key(` line.
    (tmp_path / "k.py").write_text(
        "from cryptography.hazmat.primitives.asymmetric import rsa\n"
        "key = rsa.generate_private_key(\n"
        "    public_exponent=65537,\n"
        "    key_size=1024,  # security: allow-weak-crypto\n"
        ")\n", encoding="utf-8"
    )
    assert WeakCryptoGuard().run(tmp_path, _pyprof(tmp_path)) == []

def test_weak_crypto_pragma_on_following_line_does_not_leak(tmp_path: Path) -> None:
    # #395 RC-1: a pragma on the UNRELATED following line must NOT suppress the weak-key finding
    # above it (the span slice was off-by-one).
    (tmp_path / "k.py").write_text(
        "from cryptography.hazmat.primitives.asymmetric import rsa\n"
        "import hashlib\n"
        "key1 = rsa.generate_private_key(public_exponent=65537, key_size=1024)\n"
        "digest = hashlib.md5(data).hexdigest()  # security: allow-weak-crypto\n",
        encoding="utf-8",
    )
    findings = [f for f in WeakCryptoGuard().run(tmp_path, _pyprof(tmp_path))
                if f.rule == "weak-crypto/weak-key-size"]
    assert len(findings) == 1



# #613: a triple-quoted argument holding an apostrophe used to desync the call splitter, which
# returned None, so the guard skipped the call and a real weak key_size went unreported.
def test_weak_crypto_flags_weak_key_size_after_a_triple_quoted_argument(tmp_path: Path) -> None:
    (tmp_path / "k.py").write_text(
        "from cryptography.hazmat.primitives.asymmetric import rsa\n"
        "key = rsa.generate_private_key(\n"
        "    public_exponent=65537, backend=load_backend('''the HSM's backend'''), key_size=1024\n"
        ")\n", encoding="utf-8"
    )
    findings = WeakCryptoGuard().run(tmp_path, _pyprof(tmp_path))
    assert [f.rule for f in findings] == ["weak-crypto/weak-key-size"]


def test_weak_crypto_silent_on_strong_key_size_after_a_triple_quoted_argument(tmp_path: Path) -> None:
    # FP-bait for the widening above: the call now splits, and a strong key must stay silent.
    (tmp_path / "k.py").write_text(
        "from cryptography.hazmat.primitives.asymmetric import rsa\n"
        "key = rsa.generate_private_key(\n"
        "    public_exponent=65537, backend=load_backend('''the HSM's backend'''), key_size=2048\n"
        ")\n", encoding="utf-8"
    )
    assert WeakCryptoGuard().run(tmp_path, _pyprof(tmp_path)) == []


def test_weak_crypto_pragma_quoted_in_a_string_still_fires(tmp_path: Path) -> None:
    # #1040, both checks: the pragma quoted in a string on the flagged line, or on any line of a
    # multi-line `generate_private_key(` call, is not a comment; neutral run = control.
    for note in ("# reviewed", "# security: allow-weak-crypto"):
        for source, rule in (
            (f'import hashlib\ndigest = hashlib.md5(data).hexdigest(); _note = "{note}"\n', "weak-crypto/insecure-hash"),
            (
                "from cryptography.hazmat.primitives.asymmetric import rsa\n"
                "key = rsa.generate_private_key(\n"
                "    public_exponent=65537,\n"
                f'    key_size=1024, label="{note}",\n'
                ")\n",
                "weak-crypto/weak-key-size",
            ),
        ):
            (tmp_path / "k.py").write_text(source, encoding="utf-8")
            assert [f.rule for f in WeakCryptoGuard().run(tmp_path, _pyprof(tmp_path))] == [rule], (note, source)


def test_weak_crypto_pragma_comment_on_the_calls_closing_line_still_suppresses(tmp_path: Path) -> None:
    # #1040 reach unchanged: the span runs to the call's LAST line inclusive, here its own `)` line.
    for tail, n in (("", 1), ("  # security: allow-weak-crypto", 0)):
        (tmp_path / "k.py").write_text(
            "from cryptography.hazmat.primitives.asymmetric import rsa\n"
            "key = rsa.generate_private_key(\n"
            "    public_exponent=65537,\n"
            "    key_size=1024,\n"
            f"){tail}\n", encoding="utf-8"
        )
        assert len(WeakCryptoGuard().run(tmp_path, _pyprof(tmp_path))) == n, tail
