from __future__ import annotations

import pytest

from agentsec.guards.homoglyph_source_chars import (
    _CODE_SUFFIXES,
    _CONFUSABLE_POINTS,
    _SCIENTIFIC_GREEK_POINTS,
    HomoglyphSourceCharsGuard,
)
from tests.guards._common import *  # noqa: F401,F403

# Cyrillic 'а' U+0430 (looks like Latin 'a'); Cyrillic 'о' U+043E (looks like 'o');
# Greek 'ο' U+03BF (also looks like Latin 'o') — exercises the Greek half of the confusable range.
_CYR_A = "а"
_CYR_O = "о"
_GREEK_O = "ο"
_CYR_E = "е"  # U+0435, looks like Latin 'e'
# Built with chr() rather than as literals: these are the Greek letters that are BOTH Latin
# lookalikes and standard scientific quantity symbols, i.e. the graded-medium class whose FP surface
# is the thing argued about — the shapes below must be unambiguous in this source.
_GRK_SIGMA = chr(0x03C3)
_GRK_ALPHA = chr(0x03B1)
_GRK_EPSILON = chr(0x03B5)
_GRK_RHO = chr(0x03C1)
_GRK_KAPPA = chr(0x03BA)
_GRK_NU = chr(0x03BD)
_GRK_CHI = chr(0x03C7)


def test_homoglyph_source_chars_fires_greek_mix(tmp_path: Path) -> None:
    # a Greek look-alike (U+03BF) mixed with Latin — proves the Greek branch of _CONFUSABLE_RE fires
    (tmp_path / "g.py").write_text(f"passw{_GREEK_O}rd = get_input()\n", encoding="utf-8")
    findings = HomoglyphSourceCharsGuard().run(tmp_path, mkprofile(tmp_path, features={"python"}))
    assert len(findings) == 1
    assert findings[0].rule == "homoglyph-source-chars/mixed-script-identifier"
    assert "U+03BF" in findings[0].message
    # The severity grade is per-LETTER, not per-script (#489 fresh-eyes gate). Omicron is a Latin
    # lookalike with no quantity-symbol use — mathematics avoids it precisely because it collides
    # with `o`/`0` — so a Greek homoglyph stays HIGH. This assert is what separates the shipped
    # grading from the cheaper "any Greek -> medium" split, which would demote this attack.
    assert findings[0].severity == "high"


def test_homoglyph_source_chars_fires_in_sql(tmp_path: Path) -> None:
    # a homoglyph column name in a migration (.sql now scanned, given the Postgres/RLS surface)
    (tmp_path / "migration.sql").write_text(
        f"CREATE TABLE users ({_CYR_A}dmin boolean DEFAULT false);\n", encoding="utf-8"
    )
    findings = HomoglyphSourceCharsGuard().run(tmp_path, mkprofile(tmp_path, features={"sql"}))
    assert len(findings) == 1


def test_homoglyph_source_chars_fires_mixed_identifier(tmp_path: Path) -> None:
    (tmp_path / "auth.py").write_text(f"def {_CYR_A}dmin_check():\n    return True\n", encoding="utf-8")
    findings = HomoglyphSourceCharsGuard().run(tmp_path, mkprofile(tmp_path, features={"python"}))
    assert len(findings) == 1
    assert findings[0].rule == "homoglyph-source-chars/mixed-script-identifier"
    assert findings[0].severity == "high"
    assert "U+0430" in findings[0].message


def test_homoglyph_source_chars_fires_camelcase_mix(tmp_path: Path) -> None:
    (tmp_path / "x.ts").write_text(f"const passw{_CYR_O}rd = readInput();\n", encoding="utf-8")
    findings = HomoglyphSourceCharsGuard().run(tmp_path, mkprofile(tmp_path, features={"javascript"}))
    assert len(findings) == 1


def test_homoglyph_source_chars_silent_pure_cyrillic(tmp_path: Path) -> None:
    # an all-Cyrillic identifier is legitimate non-English code, not a disguised Latin word
    (tmp_path / "ru.py").write_text("def проверка():\n    pass\n", encoding="utf-8")
    assert HomoglyphSourceCharsGuard().run(tmp_path, mkprofile(tmp_path, features={"python"})) == []


def test_homoglyph_source_chars_silent_snakecase_cross_word(tmp_path: Path) -> None:
    # get_<cyrillic word>: two pure-script segments split on '_', neither mixed
    (tmp_path / "ru2.py").write_text("get_данные = load()\n", encoding="utf-8")
    assert HomoglyphSourceCharsGuard().run(tmp_path, mkprofile(tmp_path, features={"python"})) == []


def test_homoglyph_source_chars_silent_accented_latin(tmp_path: Path) -> None:
    # café / naïve are Latin-script accented letters, not another script
    (tmp_path / "fr.js").write_text('const café = "naïve";\n', encoding="utf-8")
    assert HomoglyphSourceCharsGuard().run(tmp_path, mkprofile(tmp_path, features={"javascript"})) == []


def test_homoglyph_source_chars_silent_pure_ascii(tmp_path: Path) -> None:
    (tmp_path / "clean.py").write_text("def admin_check():\n    return True\n", encoding="utf-8")
    assert HomoglyphSourceCharsGuard().run(tmp_path, mkprofile(tmp_path, features={"python"})) == []


def test_homoglyph_source_chars_pragma_silences(tmp_path: Path) -> None:
    content = f"def {_CYR_A}dmin_check():  # security: allow-homoglyph\n    return True\n"
    (tmp_path / "legacy.py").write_text(content, encoding="utf-8")
    assert HomoglyphSourceCharsGuard().run(tmp_path, mkprofile(tmp_path, features={"python"})) == []


def test_homoglyph_source_chars_skips_prose_docs(tmp_path: Path) -> None:
    # .md is prose — bilingual text there is legitimate and out of scope
    (tmp_path / "README.md").write_text(f"The {_CYR_A}dmin panel is here.\n", encoding="utf-8")
    assert HomoglyphSourceCharsGuard().run(tmp_path, mkprofile(tmp_path, features={"python"})) == []


def test_homoglyph_source_chars_applies_universal(tmp_path: Path) -> None:
    guard = HomoglyphSourceCharsGuard()
    assert guard.applies(mkprofile(tmp_path, features={"python"})) is True
    assert guard.applies(mkprofile(tmp_path, features=set())) is True


# --- #489 review -------------------------------------------------------------------------------

def test_non_lookalike_scientific_symbols_do_not_fire(tmp_path: Path) -> None:
    # The guard matched whole Greek/Cyrillic BLOCKS, so every Greek letter counted as a homoglyph
    # and scientific / unit notation fired HIGH. `applies_when` is empty, so this hit every repo
    # containing numeric code (#489 review). None of these characters resembles a Latin letter, so
    # none of them can deceive a reviewer — which is the entire threat.
    #
    # SCOPE, stated because the old name overclaimed it (#489 fresh-eyes gate, HIGH): this pins the
    # EXCLUSION decision — mu, omega, theta, Delta and pi are not in `_CONFUSABLE_POINTS` — and
    # nothing more. It is NOT evidence that scientific notation at large is silent: alpha, epsilon,
    # rho, kappa, nu, chi, iota, upsilon and sigma ARE in the set, and their FUSED spellings fire
    # (at medium). Those are pinned by `test_fused_scientific_greek_identifiers_fire_at_medium`.
    (tmp_path / "units.py").write_text(
        "timeout_μs = 500\n"                 # micro
        "resistance = 10  # 10kΩ resistor\n"  # omega
        "angle = sinθ_value\n"                # theta
        "delta = Δt\n"                        # Delta
        "area = πr2\n",                       # pi
        encoding="utf-8",
    )
    assert HomoglyphSourceCharsGuard().run(tmp_path, mkprofile(tmp_path, features={"python"})) == []


def test_confusable_in_a_comment_does_not_fire(tmp_path: Path) -> None:
    # A confusable letter IS in scope (alpha looks like `a`), but prose in a comment resolves to
    # nothing — the threat is a poisoned IDENTIFIER. `# learning rate alpha-lr` is a note about a
    # hyperparameter, not an attack (#489 review).
    (tmp_path / "train.py").write_text("# learning rate αlr tuned by hand\n", encoding="utf-8")
    (tmp_path / "train.js").write_text("// learning rate αlr tuned by hand\n", encoding="utf-8")
    assert HomoglyphSourceCharsGuard().run(tmp_path, mkprofile(tmp_path, features={"python"})) == []


def test_confusable_in_real_code_still_fires_after_the_comment_strip(tmp_path: Path) -> None:
    # The other direction: stripping comments must not swallow a poisoned identifier on a line that
    # also carries a comment.
    (tmp_path / "cfg.py").write_text(
        f"c{_GREEK_O}nfig = load()  # learning rate αlr\n", encoding="utf-8"
    )
    findings = HomoglyphSourceCharsGuard().run(tmp_path, mkprofile(tmp_path, features={"python"}))
    assert len(findings) == 1
    assert "U+03BF" in findings[0].message


def test_dotfile_env_is_reachable(tmp_path: Path) -> None:
    # `iter_files` matches on `Path.suffix`, and `Path(".env").suffix` is `""` — so a planted
    # homoglyph in `.env` was silent while the identical content in `prod.env` fired, though the
    # docstring and design doc both claimed env files were in scope (#489 review).
    for name in (".env", ".env.local", "prod.env"):
        target = tmp_path / name
        target.write_text(f"API_K{_CYR_E}Y=abc\n", encoding="utf-8")
        findings = HomoglyphSourceCharsGuard().run(tmp_path, mkprofile(tmp_path, features={"python"}))
        assert len(findings) == 1, name
        target.unlink()


@pytest.mark.parametrize("encoding", ["utf-8", "utf-8-sig", "utf-16", "utf-16-le", "utf-16-be"])
def test_poisoned_identifier_fires_regardless_of_encoding(tmp_path: Path, encoding: str) -> None:
    # The shared `read()` decodes with `errors="ignore"`, which DROPS undecodable bytes — backwards
    # for a repository-poisoning guard, since the attacker chooses the encoding. The identical
    # poisoned identifier fired in UTF-8 and was silent in UTF-16 (#489 review). cp1251 is covered
    # separately: it is a GUESS (it accepts every byte), so it is honored only for a clearly-Russian
    # file — see `test_real_cp1251_russian_still_decodes_and_fires` and the documented residual.
    (tmp_path / "app.py").write_bytes(f"{_CYR_A}dmin_token = 1\n".encode(encoding))
    findings = HomoglyphSourceCharsGuard().run(tmp_path, mkprofile(tmp_path, features={"python"}))
    assert len(findings) == 1, encoding


@pytest.mark.parametrize("encoding", ["utf-8", "cp1251", "utf-16", "utf-16-le", "utf-16-be"])
def test_clean_ascii_source_stays_silent_in_every_encoding(tmp_path: Path, encoding: str) -> None:
    # FP-bait for the decoder fallback: a mis-decode must not manufacture confusables. UTF-16
    # accepts almost any even-length byte string, so decoding cp1251 source as UTF-16 produced CJK
    # garbage — which is why UTF-16 is tried only on a BOM or a NUL byte.
    (tmp_path / "app.py").write_bytes("admin_token = 1\n".encode(encoding))
    assert HomoglyphSourceCharsGuard().run(tmp_path, mkprofile(tmp_path, features={"python"})) == []


def test_gitignored_dotfile_env_is_still_scanned(tmp_path: Path) -> None:
    # #489 second-pass review: `.env` is almost always gitignored, so the default walk skipped it
    # and the "`.env` was unreachable" fix never fired on a real repo.
    import subprocess
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=False)
    (tmp_path / ".gitignore").write_text(".env\n", encoding="utf-8")
    (tmp_path / ".env").write_text(f"API_K{_CYR_E}Y=abc\n", encoding="utf-8")
    assert len(HomoglyphSourceCharsGuard().run(tmp_path, mkprofile(tmp_path, features={"python"}))) == 1


def test_stray_nul_does_not_send_utf8_down_the_utf16_path(tmp_path: Path) -> None:
    # #489 second-pass review: the UTF-16 branch triggered on ANY NUL in the first 4096 bytes, so an
    # ordinary UTF-8 file containing one stray NUL was decoded as UTF-16 into CJK garbage and its
    # planted homoglyph vanished. UTF-16 is now gated on NUL DENSITY.
    body = f"{_CYR_A}dmin_token = 1\n".encode() + b"\x00"
    body += b"x" * (len(body) % 2)  # even length, so a UTF-16 decode would have "succeeded"
    (tmp_path / "app.py").write_bytes(body)
    assert len(HomoglyphSourceCharsGuard().run(tmp_path, mkprofile(tmp_path, features={"python"}))) == 1


@pytest.mark.parametrize(
    ("name", "text"),
    [
        ("app.py", 'label = "voilà le résultat"\n'),
        ("app.py", 'msg = "déjà vu"\n'),
        ("i18n.json", '{"t": "au-delà"}\n'),
    ],
)
def test_cp1252_accented_text_does_not_fire(tmp_path: Path, name: str, text: str) -> None:
    # #489 second-pass review: cp1251 accepts EVERY byte, so it is a guess, not a detection —
    # ordinary Western European text decoded straight into the confusable set (`à` 0xE0 -> Cyrillic
    # `а`, this guard's own headline example), producing spurious HIGH findings on French prose.
    (tmp_path / name).write_bytes(text.encode("cp1252"))
    assert HomoglyphSourceCharsGuard().run(tmp_path, mkprofile(tmp_path, features={"python"})) == []


def test_real_cp1251_russian_still_decodes_and_fires(tmp_path: Path) -> None:
    # The other direction: the cp1251 confidence gate must not lose genuine Russian-encoded source.
    (tmp_path / "app.py").write_bytes(
        ("# проверка данных сервера\n" + f"{_CYR_A}dmin_token = 1\n").encode("cp1251")
    )
    assert len(HomoglyphSourceCharsGuard().run(tmp_path, mkprofile(tmp_path, features={"python"}))) == 1


# --- #489 review, sigma (B5) -------------------------------------------------------------------

def test_sigma_confusable_fires(tmp_path: Path) -> None:
    # WIDENING. Sigma U+03C3 was excluded on a stated rationale ("visually distinct") that Unicode's
    # confusables data contradicts: it lists sigma confusable with `o`, and the set already carried
    # sigma's lunate variant U+03F2. So `cσnfig` did not fire (#489 second-pass review, B5).
    (tmp_path / "app.py").write_text(f"c{_GRK_SIGMA}nfig = load()\n", encoding="utf-8")
    findings = HomoglyphSourceCharsGuard().run(tmp_path, mkprofile(tmp_path, features={"python"}))
    assert len(findings) == 1
    assert "U+03C3" in findings[0].message
    # Sigma IS a quantity symbol, so the shipped grading reports this attack shape at MEDIUM — the
    # knowingly-accepted cost of demoting the fused-scientific FP class (see the design doc's
    # decision record). Pinned so that neither half of the grade can move silently: nothing else in
    # this file asserted the severity of a Greek finding before (#489 fresh-eyes gate, LOW).
    assert findings[0].severity == "medium"


@pytest.mark.parametrize(
    "letter",
    [_GRK_SIGMA, _GRK_ALPHA, _GRK_EPSILON, _GRK_RHO, _GRK_KAPPA, _GRK_NU, _GRK_CHI],
)
@pytest.mark.parametrize(
    "template",
    [
        "{L} = 1.0",                    # bare symbol: a pure-Greek run
        "threshold = 3 * {L}",          # operator-separated
        "cut_3{L} = 1",                 # digit-separated (a digit splits the run)
        "{L}_max = 1",                  # underscore-separated
        "x_{L} = 1",
        "n_{L}_cut = 1",
    ],
)
def test_separated_greek_notation_stays_silent(tmp_path: Path, template: str, letter: str) -> None:
    # FP-BAIT for the widening, and the half of the separator argument that is actually TRUE. The
    # fear is a repeat of the Wave A regression where `timeout_μs` fired HIGH on every repo. Mu and
    # omega are SI UNIT symbols: `μs` / `kΩ` fuse Greek to Latin inside one run as standard notation.
    # The quantity symbols here have no fused UNIT form, so their SEPARATED spellings — a digit, an
    # underscore or an operator between the letter and the Latin — are pure-script runs and stay
    # silent, because `_LETTER_RUN` splits on all three. Their FUSED spellings do fire; that is the
    # residual, pinned by `test_fused_scientific_greek_identifiers_fire_at_medium` below.
    #
    # Parametrized over the letter class, not sigma alone: the mechanism is `_LETTER_RUN`, which has
    # nothing to do with which Greek letter it is (#489 fresh-eyes gate, MEDIUM). This supersedes the
    # deleted `test_snake_case_sigma_spellings_remain_silent`, whose five lines were a strict subset
    # of these six and which could not localize a regression (one file, `break` after the first hit).
    (tmp_path / "stats.py").write_text(template.format(L=letter) + "\n", encoding="utf-8")
    assert HomoglyphSourceCharsGuard().run(tmp_path, mkprofile(tmp_path, features={"python"})) == []


def test_unseparated_n_sigma_fires_the_accepted_residual(tmp_path: Path) -> None:
    # The residual, pinned rather than left implicit: `nσ` ("n-sigma") written with no separator IS
    # one script-mixed run and DOES fire. Accepted deliberately — it is indistinguishable from the
    # attack shape by construction, since `cσnfig` is also just Latin letters fused to a sigma. The
    # pragma is the escape hatch, and the design doc's FP section records the trade. If this test
    # ever becomes a real user complaint, the fix is a carve-out here, not silent removal of sigma.
    (tmp_path / "fit.py").write_text(f"n{_GRK_SIGMA} = 5\n", encoding="utf-8")
    findings = HomoglyphSourceCharsGuard().run(tmp_path, mkprofile(tmp_path, features={"python"}))
    assert len(findings) == 1
    assert findings[0].severity == "medium"  # a quantity symbol: graded, not carved out


def test_guard_source_carries_no_greek_or_cyrillic_literal() -> None:
    # The module docstring claims it carries none of what it detects, so the guard never flags itself
    # and the canary cannot self-match. That claim was FALSE: the comment above `_CONFUSABLE_POINTS`
    # illustrated the set with the very characters it detects (alpha, epsilon, omicron, rho and their
    # Cyrillic twins were all literals in the source). Those runs happened to be pure-script, so
    # nothing fired — the invariant held by luck, not by construction. Pinned here so the next edit
    # that fuses one of them to a Latin letter fails this test instead of self-flagging the guard.
    import agentsec.guards.homoglyph_source_chars as guard_module

    source = Path(guard_module.__file__).read_text(encoding="utf-8")
    offenders = sorted(
        {c for c in source if 0x0370 <= ord(c) <= 0x03FF or 0x0400 <= ord(c) <= 0x04FF}
    )
    assert offenders == [], (
        "guard source must describe Greek/Cyrillic by code point, never as a literal: "
        + ", ".join(f"U+{ord(c):04X}" for c in offenders)
    )


# --- #489 fresh-eyes gate: the FUSED SCIENTIFIC-LETTER residual, and its severity grade -----------
# The earlier round of this pinned sigma in camelCase. Sigma was the reported instance; the invariant
# is `_LETTER_RUN` splitting on `_`/digits/non-letters but NOT on a case change or a script change,
# applied to the nine Greek letters that are also scientific quantity symbols. So the whole class
# fires, in camelCase AND in fused snake_case, in every entry of `_CODE_SUFFIXES`.

@pytest.mark.parametrize(
    ("name", "ident"),
    [
        # camelCase — the only conventional spelling for these quantities in these languages
        ("app.ts", _GRK_SIGMA + "Value"),
        ("m.go", _GRK_SIGMA + "Threshold"),
        ("A.java", _GRK_RHO + "Max"),
        ("app.tsx", _GRK_SIGMA + "Clip"),
        ("rl.ts", _GRK_EPSILON + "Greedy"),      # epsilon-greedy, the canonical RL hyperparameter
        ("rl.go", _GRK_ALPHA + "Lr"),            # alpha learning rate
        ("heat.cs", _GRK_KAPPA + "Eff"),         # kappa, effective conductivity
        ("flow.cpp", _GRK_NU + "Turb"),          # nu, turbulent viscosity
        ("fit.ts", _GRK_CHI + "Squared"),
        # FUSED snake_case — the half the earlier "snake_case is still fine" framing missed
        ("em.py", _GRK_EPSILON + "r"),           # relative permittivity, fused in every language
        ("em.c", _GRK_EPSILON + "r"),
        ("cs.py", _GRK_RHO + "s"),               # rho_s, paper notation with the underscore omitted
        ("opt.py", _GRK_ALPHA + "t"),            # alpha_t
        ("x.py", _GRK_SIGMA + "tot"),            # physics cross-section notation
        ("x.py", _GRK_SIGMA + "pp"),
    ],
)
def test_fused_scientific_greek_identifiers_fire_at_medium(
    tmp_path: Path, name: str, ident: str
) -> None:
    # The residual, stated at the level of the invariant rather than of the reported instance
    # (#489 fresh-eyes gate). It is NOT carved out: `cσnfig` is also nothing more than Latin fused to
    # a quantity symbol, so any rule sparing these spares the attack. What carries the uncertainty is
    # the SEVERITY — medium, so a fused-notation false positive no longer breaks a downstream
    # `--fail-on high` CI gate, while every non-quantity lookalike (all Cyrillic, omicron, lunate
    # sigma, yot, the Greek capitals) stays high. Both halves are asserted here and in
    # `test_homoglyph_source_chars_fires_greek_mix`, so neither can move silently.
    (tmp_path / name).write_text(f"{ident} = 3.0;\n", encoding="utf-8")
    findings = HomoglyphSourceCharsGuard().run(
        tmp_path, mkprofile(tmp_path, features={"python", "javascript"})
    )
    assert len(findings) == 1, f"{name}: {ident}"
    assert findings[0].severity == "medium", f"{name}: {ident}"


@pytest.mark.parametrize("suffix", _CODE_SUFFIXES)
def test_every_scanned_suffix_reaches_a_fused_identifier(tmp_path: Path, suffix: str) -> None:
    # The residual is a property of `_CODE_SUFFIXES`, not of a hand-copied subset of it: the earlier
    # doc/comment listed ten suffixes, and all 25 fire — including the config/data formats, where it
    # is a camelCase KEY that fires, not just a value (#489 fresh-eyes gate, LOW).
    #
    # It is also the FN-guard for the `.env` class of bug: a suffix can sit in `_CODE_SUFFIXES` and
    # still be unreachable by the walk (`Path(".env").suffix` is `""`), which is exactly how a
    # planted homoglyph in `.env` went silent while `prod.env` fired.
    (tmp_path / f"probe{suffix}").write_text(f"{_GRK_SIGMA}Value = 1\n", encoding="utf-8")
    findings = HomoglyphSourceCharsGuard().run(tmp_path, mkprofile(tmp_path, features={"python"}))
    assert len(findings) == 1, suffix


@pytest.mark.parametrize(
    "token",
    [
        _GRK_SIGMA + "dm" + _CYR_A + "n",     # Cyrillic laundered behind a quantity symbol
        "c" + _GRK_SIGMA + "nfi" + _GREEK_O,  # omicron laundered behind a quantity symbol
        "c" + _GRK_ALPHA + "nfi" + chr(0x03F2),   # lunate sigma, likewise
    ],
)
def test_a_quantity_symbol_cannot_launder_a_run_down_to_medium(tmp_path: Path, token: str) -> None:
    # The obvious evasion of a per-letter grade: pad the run with a graded letter and hope the whole
    # finding is demoted. It is not — the grade requires EVERY confusable in the run to be a quantity
    # symbol (`issuperset`), so one non-graded letter anywhere in the run keeps it high.
    (tmp_path / "app.py").write_text(f"{token} = 1\n", encoding="utf-8")
    findings = HomoglyphSourceCharsGuard().run(tmp_path, mkprofile(tmp_path, features={"python"}))
    assert len(findings) == 1, token
    assert findings[0].severity == "high", token


def test_scientific_grade_is_a_severity_not_an_exclusion() -> None:
    # The grading must never quietly become a subtraction from the detection set — that is the
    # regression it exists to avoid (dropping the letters back out would reopen the `cσnfig` hole,
    # which is the whole reason sigma was added in the first place). Every graded letter is still a
    # detected letter; the parametrized test above proves each one still fires.
    assert _SCIENTIFIC_GREEK_POINTS <= _CONFUSABLE_POINTS
    assert len(_SCIENTIFIC_GREEK_POINTS) == 9
    # And the grade is per-letter, not per-script: the Greek members that are NOT quantity symbols
    # (omicron, lunate sigma, yot, and every Greek capital in the set) must stay high.
    assert 0x03BF not in _SCIENTIFIC_GREEK_POINTS      # omicron — the classic `o` homoglyph
    assert 0x03F2 not in _SCIENTIFIC_GREEK_POINTS      # lunate sigma, confusable with `c`
    assert 0x03F3 not in _SCIENTIFIC_GREEK_POINTS      # yot, confusable with `j`
    assert not any(0x0391 <= cp <= 0x03A9 for cp in _SCIENTIFIC_GREEK_POINTS)   # no Greek capital
    assert not any(0x0400 <= cp <= 0x052F for cp in _SCIENTIFIC_GREEK_POINTS)   # no Cyrillic
