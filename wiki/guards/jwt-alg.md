---
type: Guard
title: "jwt-alg"
description: "JWT decoded without a pinned algorithm (alg-confusion risk)."
timestamp: "2026-10-24T00:00:00Z"
guard_id: "jwt-alg"
checklist_section: ["2a"]
standards: ["OWASP:A02", "OWASP:A07", "SOC2:CC6.1"]
---

# JWT decoded without a pinned algorithm (alg-confusion risk)

_Added 2026-06-12 — gap #2 (was #1 after service-role-key shipped). The complementary static partner
to the Semgrep `agentsec-jwt-unverified-decode` rule._

---

## The threat

§2a of the checklist: *"Algorithm explicitly hardcoded server-side — never trust the `alg` header
from the token."* Two exploit shapes when a JWT is verified without pinning the algorithm:

- **RS256→HS256 algorithm confusion** — the server expects RS256 (asymmetric) but the decode
  honors the token's own `alg` header. The attacker re-signs a forged token with **HS256**, using
  the server's *public* RS256 key as the HMAC secret. The public key is, by definition, public — so
  the forgery verifies and the attacker becomes any user. Pinning `algorithms=["RS256"]` (or the one
  real algorithm) refuses the swap.
- **`alg: none`** — `algorithms=[…, "none", …]` accepts *unsigned* tokens; anyone forges any claim.

Findings carry `["OWASP:A02", "OWASP:A07"]`.

## Scope — complementary to the Semgrep pack (no double-flagging)

`agentsec/ai/semgrep-rules/python-llm.yaml::agentsec-jwt-unverified-decode` already owns
**signature-disabled** decodes (`verify_signature: False` / `verify=False`) — a *different* finding
(the signature isn't checked at all, often a deliberate non-security metadata read). This guard
therefore **skips** verification-disabled calls and only judges the *algorithm pin* of calls that
DO verify. The two are designed to partition the space, not overlap. The flagship is the proof:
its `token_validation.py` decode pins `algorithms=["HS256"]` (silent here), and its
`widget_user_sync.py` / `hwh_api_client.py` reads use `verify_signature: False` with `# nosemgrep`
(skipped here, owned by Semgrep) — agentsec reports **0** jwt-alg findings on it.

## Detection design

1. **`applies()` gate** — `"python" in profile.features` (the Python rules) or
   `"express" in profile.features` (the Node rule below).
2. **Scan** — every `.py` under `python_scan_dirs`; find `jwt.decode(` (covers PyJWT and
   python-jose, which both expose `jwt.decode`).
3. **Argument extraction** — `_call_args` does a paren-depth walk (string-literal aware) from the
   opening `(` to its match, so a **multi-line** call (as the flagship writes it) is read whole.
4. **Decision** over the argument text:
   - `verify_signature: False` / `verify=False` present → **skip** (Semgrep's domain).
   - `algorithms=[… "none" …]` (string literal) → **high**, `jwt-alg/none-algorithm`.
   - no `algorithms=` kwarg at all → **medium**, `jwt-alg/unpinned-algorithms`.
   - `algorithms=` present (list or a variable) → **safe** (a variable is given the benefit of the
     doubt to avoid false positives).
5. **Opt-out** — `# security: allow-unpinned-jwt` on the decode line or the line above.
6. **Node `jsonwebtoken` (`jwt-alg/js-verify-disabled`, critical)** — `jwt.verify(token, false,
   ...)` passes the literal `false` as the key, which disables signature verification. Matched per
   line on product `.js`/`.jsx`/`.ts`/`.tsx` files after comment blanking. **Live code only
   (#1055):** the call's `(` and the `false` must both be live code on the anchor mask
   (`js_code_matches` over `strip_js_comments(text, strip_strings=True, keep_substitutions=True)`),
   so a call spelled out in a docs or log string, or a `false` that sits in template text, does
   not fire, while a call inside a `${...}` substitution still does. Every match on the line is
   tried, so a quoted copy cannot hide a real call after it. The search stays per line: the
   regex's `[^,]+` also crosses newlines, so a whole-file search is quadratic (#1157). Opt-out:
   `// security: allow-jwt-verify-disabled` on the `verify` line.

Unpinned is **medium** (modern PyJWT ≥2.0 *requires* `algorithms` and errors without it, so the
live risk is library- and version-dependent — python-jose and old PyJWT are the exposed cases);
explicit `none` is **high** (unambiguous, every library).

## When NOT to flag

A pinned decode (`algorithms=["HS256"]`, or `algorithms=SOME_CONST`) is clean. A signature-disabled
decode is out of scope (Semgrep + it's often a deliberate metadata read). `jwt.get_unverified_*`
helpers, encoding, and non-`jwt.decode` verification are not matched. The pragma covers a reviewed
deliberate unpinned read.

## Tests

| Test | What it checks |
|---|---|
| `test_jwt_alg_flags_unpinned_decode` | verifying decode with no `algorithms=` → MEDIUM |
| `test_jwt_alg_flags_none_algorithm` | `algorithms=["HS256","none"]` → HIGH |
| `test_jwt_alg_pinned_multiline_is_silent` | flagship-shaped multi-line pinned decode → silent |
| `test_jwt_alg_verify_disabled_is_skipped` | `verify_signature: False` read → silent (Semgrep's) |
| `test_jwt_alg_pragma_opt_out` | `# security: allow-unpinned-jwt` → silent |
| `test_jwt_alg_not_applicable_without_python` | `applies()` False without python |
| `test_jwt_alg_js_verify_spelled_in_a_string_stays_silent` | #1055 FP direction: `jwt.verify(token, false)` in a string or template text, or with the `false` in template text, does not fire |
| `test_jwt_alg_js_real_verify_disabled_still_fires` | #1055: the real call fires, including one nested in `${...}` and one after a quoted copy on the same line |
| `test_jwt_alg_js_pragma_still_suppresses_a_code_anchored_call` | the pragma still silences a finding the anchor rule kept |
| `test_jwt_alg_js_scan_stays_linear_on_comma_free_verify_lines` | the per-line scan stays linear on comma-free `jwt.verify(` lines (`[^,]+` crosses newlines, so a whole-file search is quadratic, #1157), and a real call after them still fires |

Liveness: the canary plants `jwt.decode(token, key, algorithms=["none"])` (`agentsec/canary.py`),
so `doctor --canary` proves the guard fires end-to-end.

## Known bypasses

- **`algorithms` from an untrusted source** — `algorithms=request.headers["alg"]` (or any variable)
  is treated as pinned; the guard can't see the value. The confusion attack via a *variable* fed
  from the token is not caught (rare; would need data-flow).
- **Indirect decode** — a wrapper (`my_decode(token)`) or an aliased import (`from jwt import decode
  as d`) evades the `jwt.decode(` literal match.
- **Other JWT libraries** — `authlib`, `python-jws`, manual `hmac` verification aren't matched.
- **JS/TS anchoring (#1055).** Residual: the anchor mask inherits the #543 sub-lexer residual: a `{` inside a regex or comment in one `${...}` substitution, then a `}` in a later one, rebalances the frame, so the code between the two reads as template text and an anchor there is not code (the accepted trade pinned by `test_strip_js_comments_anchor_mask_balanced_desync_masks_code_accepted_trade`); a call there is missed, which errs toward
  silence.
- **Pathological string literals** — the paren walk handles quotes/escapes but not every exotic
  f-string nesting; a decode buried in such would be mis-bounded (degrades to skip, not crash).

## What this guard does NOT prove

That JWT handling is secure — only that a `jwt.decode` call pins its algorithm (or is deliberately
unverified). It does not check the key's secrecy/rotation, `audience`/`issuer`/expiry validation,
the strength of the signing secret, or token storage on the client (`2a-tokens-not-in-localstorage`,
which stays manual).

# Citations

[1] agentsec checklist item `2a-jwt-alg-pinned` (§2a)
[2] OWASP:A02
[3] OWASP:A07
[4] SOC2:CC6.1
