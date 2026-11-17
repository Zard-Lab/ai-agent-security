---
type: Guard
title: "homoglyph-source-chars"
description: "No homoglyph / mixed-script confusable identifiers in source."
timestamp: "2026-07-22T01:40:50Z"
guard_id: "homoglyph-source-chars"
checklist_section: ["3b"]
standards: ["OWASP-LLM:LLM01"]
---

# No homoglyph / mixed-script confusable identifiers in source

_Dean — 2026-07-22_

---

## The threat

Google's "Vibe Coding Agent Security and Evaluation" (2026) lists homoglyphs alongside zero-width
payloads as a repository-poisoning vector. **Who reaches it:** anyone who can land a commit / a
dependency / pasted context. **With what privilege:** none special — the payload hides in plain sight.
**To what effect:** a Latin letter is replaced by a visually identical character from another script
(Cyrillic `а` U+0430 for `a`, Greek `ο` U+03BF for `o`), so `аdmin_check` looks exactly like
`admin_check` to a reviewer but is a different symbol. A call, import, or allowlist entry silently
resolves somewhere the reviewer cannot see, and an agent replicating the code spreads it across files.
Findings carry **OWASP-LLM:LLM01** (prompt injection / repo poisoning) and **CWE-1007** (Insufficient
Visual Distinction of Homoglyphs). This is the visible-but-confusable sibling of `invisible-unicode`
(which catches *invisible* smuggling).

## Why it's often introduced / Why this guard fits the stack

It is rarely introduced by accident — it is an attack. It enters a FastAPI + React + LLM/RAG app through
a poisoned dependency, a copy-pasted "helpful" snippet from a forum/RAG context, or a malicious PR that a
reviewer waves through because the token looks right. The bad shape:

```python
def аdmin_check():   # 'а' is Cyrillic U+0430 — not the admin_check you think you are calling
    return True
```

## Detection design

1. **applies()** — `True` (universal): homoglyph poisoning is a property of text, not a stack (mirrors
   `invisible-unicode`).
2. **Files scanned** — code + config suffixes only (`.py/.js/.ts/.jsx/.tsx/.go/.rs/...`, JSON/YAML/TOML/
   INI/env) via `iter_files`, **plus a name-based pass for `.env` / `.env.*`**: `iter_files` matches on
   `Path.suffix`, and `Path(".env").suffix` is `""`, so a dotfile env was unreachable — a planted
   homoglyph in `.env` was silent while the identical content in `prod.env` fired, though both this doc
   and the docstring claimed env files were in scope (#489 review). Prose (`.md`/`.txt`/`.rst`/`.html`/
   `.csv`) is deliberately excluded, where bilingual mixed-script text is legitimate and noisy.
   **Decoding:** the file is decoded as UTF-8, then (on a BOM or a NUL byte) UTF-16, then cp1251 —
   NOT via the shared `read()`, whose `errors="ignore"` drops undecodable bytes. That fail direction is
   backwards for a repository-poisoning guard, since the attacker chooses the encoding: the identical
   poisoned identifier fired in UTF-8 and was silent in cp1251 and UTF-16 (#489 review).
   **Comments are blanked** (per-suffix: `#`, `//`/`/* */`, SQL `--`) before scanning — the threat is a
   poisoned identifier, and mathematical prose in a comment legitimately mixes scripts. The pragma is
   read from the comment-only view of the same text (#424; item 4 names the suffixes that still match raw).
3. **Patterns** — a whole-file fast path (`_CONFUSABLE_RE` search for any confusable char, built via
   `chr()` from a frozenset of code points so the guard's own source carries no literal confusable) skips
   the overwhelming majority of files before any per-line work. On a file that has confusables, each
   maximal **letter-run** (`[^\W\d_]+` — one identifier sub-segment, split on `_`/digits/`$`) is checked
   for containing BOTH an ASCII-Latin letter and a confusable.

   **The confusable set is a curated LIST of Latin-lookalike code points, not the whole Greek/Cyrillic
   blocks.** Block matching treated every Greek letter as a homoglyph, so scientific and unit notation
   fired HIGH — `timeout_μs`, `10kΩ`, `sinθ`, `Δt`, `πr`. With `applies()` returning True this reached
   every repo containing numeric or scientific code (#489 review). None of those characters resembles a
   Latin letter, so none can deceive a reviewer, which is the whole threat. Included: the Greek/Cyrillic
   letters Unicode's confusables data maps onto ASCII (omicron/о for `o`, rho/р for `p`, alpha/а for `a`,
   epsilon/е for `e`, …). Excluded: everything visually distinct — mu, omega, theta, delta, pi, lambda,
   phi, psi.

   **Sigma (U+03C3) is included**, added on the #489 second-pass review. It had been excluded on the
   stated rationale that it is visually distinct, which Unicode's confusables data contradicts (it lists
   sigma confusable with `o`), and the set already carried sigma's *lunate* variant U+03F2 (confusable
   with `c`) — so excluding the base form while including its variant was the actual inconsistency.
   Sigma is one of the nine letters that are *also* scientific quantity symbols, which is where this
   guard's whole false-positive surface lives — see **The fused scientific-letter residual** and **The
   severity grade** under *When NOT to flag* for that analysis and the decision taken on it.
   Splitting on `_` means a `get_<cyrillic-word>` name is two pure-script segments (silent); only a mix
   WITHIN one segment fires. One finding per file (the first mixed token). `.sql` is scanned (a homoglyph
   column/table name in a migration is the same threat on the Postgres/RLS surface).
4. **Pragma** — a `# security: allow-homoglyph` comment (`//` / `--` in the file's own syntax) anywhere in the
   file. For the suffixes that have a comment dialect (`comment_dialect_for`: Python, JS/TS, Go, Java, Ruby,
   PHP, SQL, YAML, and the `#`-comment configs `.toml` / `.ini` / `.cfg` / `.env`) a string literal quoting
   the phrase does not count (#424). `.rs`, `.c` / `.h` / `.cpp`, `.cs`, `.vue`, `.svelte` and `.json` have no
   dialect yet, so for those files the match still runs on the raw text and a quoted phrase still suppresses.
5. **Severity / rule / standards** — `homoglyph-source-chars/mixed-script-identifier`
   (**high**, or **medium** when every confusable in the run is a scientific quantity symbol — see
   *The severity grade* below), `["OWASP-LLM:LLM01", "CWE-1007"]`.

## When NOT to flag

An all-one-script identifier is fine: a pure-Cyrillic word or a Greek `π` constant is not a disguised
Latin word — silent. Accented Latin (`café`, `naïve`, `Zürich`) stays in the Latin script — silent. A
snake_case identifier joining two whole words from different scripts (a Latin `get_` + a Cyrillic
suffix) splits into pure-script segments — silent. Prose docs are out of scope entirely. Use the pragma
for an audited, intentional mixed-script literal.

**Scientific notation written with a letter that is NOT a Latin lookalike is silent** — mu, omega,
theta, delta, pi, lambda, phi and psi are not in the confusable set, so `timeout_μs`, `10kΩ`, `sinθ`,
`Δt` and `πr` cannot fire whatever they are fused to. Notation written with a letter that **is** a Latin
lookalike — alpha, epsilon, iota, kappa, nu, rho, sigma, upsilon, chi — **does** fire whenever it is
fused to Latin inside one letter run, in any language and in snake_case too. See *The fused
scientific-letter residual* below; that residual is real, measured, and graded **medium**. Confusables
appearing only in a **comment** are silent, because comments are blanked before scanning.

> An earlier version of this paragraph claimed flatly that "scientific and mathematical notation is
> silent … the symbols used for it are not in the confusable set". Measurement falsifies that: the
> 2026-08-03 fresh-eyes gate on #489 fired `εGreedy` (.ts), `αLr` (.go), `ρMax` (.java), `κEff` (.cs),
> `νTurb` (.cpp), `χSquared` (.ts), `εr` (.c and .py), `ρs` (.py), `αt` (.py) and a `{"αLr": …}` JSON
> key — all at HIGH. The claim was written when the FP fix was "remove the letter from the set", which
> is only possible for letters that are not lookalikes.

**The mu/omega analysis, and what it actually generalizes to.** Sigma is the standard-deviation symbol,
so widening to it looked like the mistake that made `timeout_μs` fire HIGH on every repo. That analysis
was right about the mechanism and wrong about its reach:

- **Mu and omega are SI unit symbols.** `μs` (microsecond) and `kΩ` (kilohm) fuse a Greek letter to a
  Latin letter *inside one letter run*, as standard notation. That is why block matching fired on them —
  and, since neither resembles a Latin letter, why removing them from the set cost no detection at all.
- **The quantity symbols have no fused UNIT form, so their SEPARATED spellings are silent.** `3σ`,
  `σ_max`, `x_σ`, `n_σ_cut`, `5 * σ`, the bare `σ` — `_LETTER_RUN` splits on digits, `_` and operators,
  so each is a pure-script run. Pinned across the whole letter class by
  `test_separated_greek_notation_stays_silent`.
- **But "separated" was doing all the work, and nothing guarantees it.** That is the residual below.

### The fused scientific-letter residual

**The invariant.** `_LETTER_RUN` splits on `_`, on digits and on non-letters, but **not** on a case
change and **not** on a script change. So *any* confusable fused to Latin inside one run fires — in
**every entry of `_CODE_SUFFIXES`** (all 25 measured, `.rs`/`.h`/`.pyi`/`.vue`/`.svelte` and the whole
config/data set included), in camelCase and in snake_case alike. Nine of the Greek letters in the set
are also standard scientific **quantity symbols** — alpha, epsilon, iota, kappa, nu, rho, sigma,
upsilon, chi — and their fused spellings are ordinary, non-malicious code. Measured firing:

| surface | identifier | what it is in real code |
|---|---|---|
| `.ts` | `σValue`, `σMax`, `εGreedy`, `χSquared` | stddev value/threshold; epsilon-greedy; chi-squared |
| `.tsx` | `σClip` | clamp at n sigma |
| `.go` | `σThreshold`, `αLr` | stddev threshold; alpha learning rate |
| `.java` | `σValue`, `ρMax` | stddev; correlation max |
| `.cs` / `.cpp` / `.c` | `κEff`, `νTurb`, `εr` | conductivity; turbulent viscosity; relative permittivity |
| `.py` | `σtot`, `σpp`, `εr`, `ρs`, `αt` | paper notation with the underscore omitted — **snake_case fires too** |
| `.json` / `.yaml` / `.toml` / `.env` | `{"αLr": 0.01}` | a camelCase **key**, not only a value |

camelCase is the *only* conventional spelling for these quantities in TypeScript, Go, Java and C#, and
`applies()` is universal — so this is the widest residual the guard carries. It is stated at the level of
the invariant rather than of sigma (the reported instance) because the mechanism has nothing to do with
which Greek letter it is. Pinned by `test_fused_scientific_greek_identifiers_fire_at_medium` (camelCase
**and** fused snake_case, seven letters) and `test_every_scanned_suffix_reaches_a_fused_identifier`.

**Accepted residual, same class:** an *unseparated* `nσ` ("n-sigma") is one script-mixed run and fires,
pinned by `test_unseparated_n_sigma_fires_the_accepted_residual`.

### The severity grade — the document-vs-fix decision (2026-08-03)

The version of this doc before 2026-08-03 said: *"If it turns up as a real complaint in corpus-scan or
user triage, the fix is an explicit carve-out with its own FP analysis, not silently dropping sigma back
out of the set."* **That evidence arrived, pre-merge, and it did not come from sigma.** The #489
fresh-eyes gate scanned 11 local roots (this repo's own `site-packages` plus ten neighbouring
repositories) and produced exactly **one** finding in the entire corpus — a false positive:

```
high  pygments/lexers/lean.py:32   token `Zα` (U+03B1)
      "(?![λΠΣ])[_a-zA-Zα-ωΑ-Ωϊ-ϻἀ-῾℀-⅏𝒜-𝖟]"      <- a Unicode char-class in a Lean lexer regex
```

Pygments is a transitive dependency of this project's own dev environment. Measured precision on the
available corpus: **0 true positives / 1 finding**, and the letter was alpha.

**Decision: keep the detection, grade the severity.** Detection is unchanged — every letter still fires,
and no carve-out was added. What changed is that a finding whose confusables are **all** quantity
symbols (`_SCIENTIFIC_GREEK_POINTS`) is reported **medium**; everything else — any Cyrillic, any Greek
capital, omicron U+03BF, lunate sigma U+03F2, yot U+03F3 — stays **high**.

The change can only demote, never promote and never add: the detection set is untouched, so the finding
*set* is identical by construction and only the grade can move. Measured before/after over 12 local
roots (this repo, its `site-packages`, and ten neighbouring repositories): **identical finding set, zero
promotions, zero new findings, one demotion** — the Pygments FP, now below the default gate.

*Why not a carve-out (the "fix" branch).* No rule spares the FPs without sparing the attack: `cσnfig` is
also nothing more than Latin fused to a quantity symbol, and every positional rule tried (Greek-then-
uppercase, leading position) is defeated by choosing another position — `οAuthToken` reads as
`oAuthToken`. Dropping the letters back out of the set would reopen the hole that adding sigma closed.

*Why not "document and leave it" (the previous branch).* The guard's `applies()` is universal and `high`
is the default `--fail-on`, so every one of these FPs **breaks a downstream user's CI gate**. That is a
larger trade than "an accepted residual" conveys, and this guard has already taken the cheaper direction
once for exactly this reason: the cp1251 confidence gate accepts a *false negative* to avoid a spurious
HIGH on French prose, "given `applies()` is universal". A demotion is strictly cheaper than the miss
already accepted there.

*Why per-letter and not per-script* (the gate offered the simpler "any Cyrillic → high, Greek-only →
medium"): both axes that matter partition on the letter, not the script. **Legitimacy** — omicron,
lunate sigma and yot have no quantity-symbol use, and neither do the Latin-lookalike Greek capitals;
mathematics *avoids* the letters that collide exactly with Latin, which is precisely what makes them the
best poisoning tools. **Confusability** — the graded-down letters are the weakest lookalikes in the set;
a reviewer spots `cσnfig` far more readily than the omicron `cοnfig`. A flat script split would demote
`passwοrd`, this guard's own Greek headline example, and it is pinned at high by
`test_homoglyph_source_chars_fires_greek_mix` for exactly that reason.

*The cost, accepted knowingly.* An attacker who picks one of the nine lands at **medium** and no longer
trips a default `--fail-on high` gate — `cσnfig` included. The finding is still emitted, with the same
message plus a sentence explaining the grade. This is a real weakening against a letter-aware attacker
and is the price of not breaking every scientific codebase's CI. **The next escalation trigger** is
evidence of an actual poisoning attempt using one of the nine, or a triage complaint that a medium
finding was ignored because of its grade; the response would then be a discriminator on *context*
(e.g. identifier position within the file's declared symbols), not another severity move.

**Known false-positive class (config keys and values):** unlike prose docs, JSON/YAML/TOML/INI/`.env`/
`.sql` are scanned, and the check distinguishes neither an identifier from a string *value* nor a value
from a **key** — a camelCase key such as `{"αLr": 0.01}` fires exactly like the `.ts` identifier does
(measured; see the residual table above). A config or locale value that
packs a mixed-script word into a single token (a transliterated brand, an i18n string that glues two
scripts without a separator) can therefore false-positive. It is narrow — ordinary bilingual text uses
separate words, which split into pure-script tokens and stay silent — so it is left as an accepted
residual with the `# security: allow-homoglyph` comment as the escape hatch, rather than adding
value-vs-key parsing per format. (`.py`/`.js`/`.ts` string content is likewise scanned, not just
identifiers; the mix-within-one-token requirement is the FP defense there too.)

## Tests

Every `test_*` in `tests/guards/test_homoglyph_source_chars.py` is listed. (The table had silently
rotted to 17 of 27 rows by the 2026-08-03 gate — there is no drift test enforcing it, so re-check the
count when adding a test.)

| Test | What it checks |
|---|---|
| `test_homoglyph_source_chars_fires_mixed_identifier` | `аdmin_check` (Cyrillic а) → high, names U+0430 |
| `test_homoglyph_source_chars_fires_camelcase_mix` | Cyrillic mixed within a segment fires |
| `test_homoglyph_source_chars_fires_greek_mix` | a Greek U+03BF mix fires — and is **high**: the grade is per-letter, not per-script |
| `test_homoglyph_source_chars_fires_in_sql` | a homoglyph column name in a `.sql` migration fires |
| `test_homoglyph_source_chars_silent_pure_cyrillic` | all-Cyrillic `проверка` stays silent |
| `test_homoglyph_source_chars_silent_snakecase_cross_word` | `get_данные` (split segments) stays silent |
| `test_homoglyph_source_chars_silent_accented_latin` | `café` / `naïve` (Latin accents) stay silent |
| `test_homoglyph_source_chars_silent_pure_ascii` | plain ASCII stays silent |
| `test_homoglyph_source_chars_pragma_silences` | the opt-out pragma silences the file |
| `test_homoglyph_source_chars_skips_prose_docs` | a `.md` doc is out of scope |
| `test_homoglyph_source_chars_applies_universal` | applies() is universal (True) |
| `test_non_lookalike_scientific_symbols_do_not_fire` | FP-bait (#489): micro/omega/theta/delta/pi are *not in the set*. Pins the exclusion decision and **nothing more** — the lookalike quantity symbols do fire (renamed from `test_scientific_and_unit_symbols_do_not_fire`, which overclaimed) |
| `test_confusable_in_a_comment_does_not_fire` | FP-bait (#489): a confusable in a `#`/`//` comment is prose, not an identifier |
| `test_confusable_in_real_code_still_fires_after_the_comment_strip` | the other direction: a poisoned identifier on a line that also has a comment |
| `test_dotfile_env_is_reachable` | FN-guard (#489): `.env`, `.env.local` and `prod.env` all scanned |
| `test_gitignored_dotfile_env_is_still_scanned` | FN-guard (#489 second pass): a gitignored `.env` is still walked |
| `test_poisoned_identifier_fires_regardless_of_encoding` | FN-guard (#489): the same identifier fires in UTF-8/UTF-8-sig/UTF-16 (5 encodings) |
| `test_clean_ascii_source_stays_silent_in_every_encoding` | FP-bait: the decoder fallback must not manufacture confusables from a mis-decode |
| `test_stray_nul_does_not_send_utf8_down_the_utf16_path` | FN-guard (#489 second pass): UTF-16 is gated on NUL *density*, not one stray NUL |
| `test_cp1252_accented_text_does_not_fire` | FP-bait (#489 second pass): French/`i18n` cp1252 text must not decode into the confusable set |
| `test_real_cp1251_russian_still_decodes_and_fires` | the other direction: the cp1251 confidence gate must not lose genuine Russian source |
| `test_sigma_confusable_fires` | `cσnfig` fires (the B5 widening) — at **medium**, the accepted cost of the grade |
| `test_separated_greek_notation_stays_silent` | FP-bait: separated spellings (`3σ`, `σ_max`, `x_σ`, `n_σ_cut`, `5 * σ`, bare) stay silent — for all seven letters, not just sigma |
| `test_unseparated_n_sigma_fires_the_accepted_residual` | `nσ` fires at medium: the residual is graded, not carved out |
| `test_fused_scientific_greek_identifiers_fire_at_medium` | the residual at the level of the invariant: 15 fused camelCase **and** snake_case cases across `.ts/.tsx/.go/.java/.cs/.cpp/.c/.py`, each **medium** |
| `test_every_scanned_suffix_reaches_a_fused_identifier` | every entry of `_CODE_SUFFIXES` (25) reaches a fused identifier — the FN-guard for the `.env`-style unreachable-suffix bug |
| `test_a_quantity_symbol_cannot_launder_a_run_down_to_medium` | the evasion of a per-letter grade: one non-graded confusable anywhere in the run keeps it high |
| `test_scientific_grade_is_a_severity_not_an_exclusion` | `_SCIENTIFIC_GREEK_POINTS` ⊆ `_CONFUSABLE_POINTS`, is 9 letters, and holds no Cyrillic / Greek capital / omicron / lunate sigma / yot |
| `test_guard_source_carries_no_greek_or_cyrillic_literal` | the module's self-purity claim, read off its own source |

## Known bypasses

Scripts beyond the two implemented blocks have Latin lookalikes too and are not covered: the adjacent
**Cyrillic Supplement (U+0500–U+052F)** and **Greek Extended (U+1F00–U+1FFF)** blocks (further
Cyrillic/polytonic-Greek letters), plus Armenian, Cherokee, and fullwidth Latin. A homoglyph forming an
all-one-non-Latin-script token that still visually reads as Latin (every letter a lookalike, so the token
has zero ASCII-Latin characters) has nothing to trip the ASCII-Latin-AND-confusable mix test — a real
residual, since mixed-script is the low-FP proxy, not full confusable-skeleton normalization. `_LETTER_RUN`
splits on the ASCII `_` and non-letters but not the broader Unicode connector-punctuation category (`Pc`,
e.g. fullwidth low line U+FF3F), so a separator built from one of those would not split a run. Prose files
are unscanned by design.

**Encoding residual (deliberate).** cp1251 is a GUESS, not a detection — it accepts every byte, so
ordinary cp1252/Latin-1 text decodes straight into the confusable set (`à` 0xE0 becomes Cyrillic `а`,
this guard's own headline example). A minimal cp1251-encoded poison is *byte-identical in structure*
to French prose: `voilà` is four Latin letters plus 0xE0, and a poisoned `àdmin` is 0xE0 plus four
Latin letters. No heuristic separates them. So cp1251 is honored only when the decode yields several
NON-lookalike Cyrillic letters — i.e. the file is clearly Russian. The trade: a cp1251 file whose
only Cyrillic is the confusable itself is missed, in exchange for never firing a spurious HIGH on
French, Spanish or Portuguese text. Given `applies()` is universal, that is the right direction.
UTF-8 and UTF-16 (BOM'd and BOM-less) are real detections and carry no such caveat; BOM-less UTF-16
is gated on NUL DENSITY, since mostly-ASCII UTF-16 is ~50% NUL bytes while a UTF-8 file with one
stray NUL is ~0%.

**Gate bypass by letter choice (deliberate, from the severity grade).** An attacker who poisons an
identifier with one of the nine scientific quantity symbols rather than a Cyrillic letter or an omicron
gets a **medium** finding, which does not trip the default `--fail-on high` CI gate. The finding is
still emitted and still says exactly what it is; only the gate changes. This is the cost recorded in
*The severity grade* above, taken because the same letters produce measured false positives on ordinary
scientific code and `applies()` is universal. A user who wants no such bypass runs `--fail-on medium`.
Padding a run with a quantity symbol does **not** launder a Cyrillic or omicron poisoning down to
medium — the grade requires *every* confusable in the run to be a quantity symbol
(`test_a_quantity_symbol_cannot_launder_a_run_down_to_medium`).

A confusable placed only in a **comment** is no longer reported — deliberate (see Detection design), but
it does mean a reviewer is not warned about a comment engineered to look like adjacent code. Legacy
**single-byte encodings other than cp1251** (koi8-r, iso-8859-5) decode as cp1251, since every byte is
valid there, so a confusable may land on a different Cyrillic letter and go unmatched; cp1251 is the
dominant one and full charset detection is out of scope. Any Greek/Cyrillic letter NOT on the curated
lookalike list is now out of scope by construction — a token mixing Latin with, say, a lone `θ` is
silent, which is the intended trade for the scientific-notation FP class.

## What this guard does NOT prove

Silence does not mean the source is free of confusables — only that no scanned code/config token mixes
ASCII-Latin with Cyrillic/Greek. It does not do full Unicode confusable-skeleton normalization (an
all-lookalike token in a single non-Latin script is missed), does not cover scripts outside Cyrillic/
Greek, and does not scan prose. A **passing CI gate** proves even less than silence does: at the default
`--fail-on high`, a green run is consistent with medium findings from the graded letters, so read the
report rather than the exit code. Pair with `invisible-unicode` for the invisible-smuggling half of the
repo-poisoning threat.

# Citations

[1] agentsec checklist item `3b-homoglyph-source-scan` (§3b)
[2] OWASP-LLM:LLM01
