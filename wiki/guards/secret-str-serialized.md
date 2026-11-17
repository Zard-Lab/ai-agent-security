---
type: Guard
title: "secret-str-serialized"
description: "Pydantic SecretStr field leaked via serialization into a log/APM sink."
timestamp: "2026-08-24T00:00:00Z"
guard_id: "secret-str-serialized"
checklist_section: ["10"]
standards: ["OWASP:A02", "OWASP:A09"]
---

# Pydantic SecretStr field leaked via serialization into a log/APM sink

_Author — 2026-08-24_

---

## The threat

Pydantic's `SecretStr` masks `repr()`/`str()` output (`SecretStr('**********')`), which
gives developers false confidence that logging a model instance is safe. That mask does
**not** survive serialization: `.dict()`, `.model_dump()`, `.model_dump_json()`, and
`dict(model_instance)` all return the raw, unmasked secret value. A model with a
`SecretStr`-typed field, whose instance (or its serialized output) then flows into a
`logger.*(...)`/`log.*(...)`/`print(...)`/Sentry-or-APM call, leaks the "protected" secret
in full — a real secret-exposure class made worse by the fact that the mask is exactly what
makes developers believe it's safe.

Sourced from a real-world incident write-up: a team used `SecretStr` for password/token
fields, confirmed the console output showed asterisks, and shipped a request-logging
middleware that called `.dict()` on the validated model before logging it — the "protected"
field went out in plaintext on every request.

## Detection design

1. **applies() gate:** `"python" in profile.features`.

2. **Files scanned:** All `.py` files via `iter_files`/`python_scan_dirs`, minus
   `is_nonproduct_path`. File-scoped, mirroring `sensitive_logging.py`.

3. **Pattern, two rules:**
   - Find `class X(...BaseModel...):` definitions with at least one field annotated
     `SecretStr` (or `Optional[SecretStr]` / `SecretStr | None` — the field's type text just
     has to mention `SecretStr` somewhere).
   - Find variable bindings to an instance of such a model (`auth = UserAuth(...)`,
     `auth: UserAuth = UserAuth(...)`) — the "secret-model instance variable" set.
   - Scan `logger.*`/`log.*`/`print(`/`(sentry_sdk.)?capture_exception`/`capture_message(`
     call sites (same call-site shape as `sensitive-logging`'s own sink detection, plus
     `print`/APM). Within the call's argument text (non-interpolated string-literal prose
     stripped, f-string `{...}` interpolations kept — a bare mention of the variable name
     in a log *message* doesn't fire):
     - `var.dict(`, `var.model_dump(`, `var.model_dump_json(`, or `dict(var)` → HIGH,
       `secret-str-serialized/serialized-logged` — the sneaky case, since the code LOOKS
       safe (a bare `print(auth)` shows asterisks) but the serialized form does not mask.
     - a bare mention of `var` as a standalone argument (not immediately followed by `.`,
       i.e. not an attribute-access chain into one specific field) → HIGH,
       `secret-str-serialized/instance-logged`.

4. **Deliberately NOT flagged — an explicit, deliberate field-level unmask.**
   `var.password.dict(` never matches (the character after `var` is `.`, so the
   bare-instance pattern requires no dot at all, and the serialized-output pattern requires
   `var` to be *directly* followed by `.dict`/`.model_dump`/`.model_dump_json`, not a field
   access first). So `auth.password.get_secret_value()` and `str(auth.password)` both stay
   silent — logging one `SecretStr` field, explicitly unmasked, is a different (already
   fairly obvious) mistake, not this guard's target. `str(auth)` (the whole INSTANCE
   wrapped in `str()`, no field access) still fires as `instance-logged`: `str()` doesn't
   require `.get_secret_value()`, and the instance itself is still flowing into the sink.

5. **Inline opt-out pragma:** `# security: allow-secret-str-log` on the sink line or the
   line above.

6. **Severity and rule:** `"high"` for both rules, standards `["OWASP:A02", "OWASP:A09"]`.

## When NOT to flag

- A `SecretStr`-typed model that's never logged or serialized at all.
- A model with no `SecretStr` field, even if it's freely logged/serialized.
- An explicit, deliberate field-level unmask (`.get_secret_value()`, `str(instance.field)`)
  — that's a different, already-obvious mistake, not this guard's target.
- The sink line mentions the variable name only inside non-interpolated log-message prose
  (`logger.info("processing auth request")`), not as an actual argument.
- The file contains `# security: allow-secret-str-log`.

## Tests

| Test | What it checks |
|---|---|
| `test_secret_str_serialized_flags_dict_serialize` | Fires: `logger.info(auth.dict())` |
| `test_secret_str_serialized_flags_model_dump_json` | Fires: `.model_dump_json()` variant |
| `test_secret_str_serialized_flags_dict_call_wrap` | Fires: `dict(auth)` wrap form |
| `test_secret_str_serialized_flags_bare_instance_print` | Fires: `print(auth)`, bare instance |
| `test_secret_str_serialized_flags_str_wrapped_instance` | Fires: `str(auth)` whole-instance wrap |
| `test_secret_str_serialized_flags_sentry_capture` | Fires: `sentry_sdk.capture_message(auth.dict())` |
| `test_secret_str_serialized_flags_optional_secretstr_field` | Fires: `Optional[SecretStr]` field variant |
| `test_secret_str_serialized_silent_when_never_logged` | Silent: model never reaches a sink |
| `test_secret_str_serialized_silent_without_secretstr_field` | Silent: model has no `SecretStr` field |
| `test_secret_str_serialized_silent_on_explicit_get_secret_value` | Silent: `.get_secret_value()` explicit unmask |
| `test_secret_str_serialized_silent_on_explicit_str_field` | Silent: `str(auth.password)` field-level wrap |
| `test_secret_str_serialized_silent_on_message_prose` | Silent: variable name only in log message text |
| `test_secret_str_serialized_pragma_opt_out` | Silent: pragma present |
| `test_secret_str_serialized_not_applicable_without_python` | `applies()` gate |

## Known bypasses (documented, not fixed — same class of limitation `sensitive-logging` accepts)

- No data-flow across files, or through a renamed/reassigned variable.
- A model instantiated inline as a call argument (`logger.info(UserAuth(...).dict())`) is
  missed — no prior binding to track.
- A custom logging wrapper whose call shape doesn't match the recognized sink patterns
  evades it.

## What this guard does NOT prove

- That the sink call actually executes on the code path taken (a log statement inside a
  rarely-hit branch still fires — same design as every other presence-based guard here).
- That the field is genuinely sensitive in context — a `SecretStr` used for something
  low-stakes still fires, matching the type's own stated intent.

# Examples

```python
class UserAuth(BaseModel):
    username: str
    password: SecretStr

# Fires — auth.dict() unmask the SecretStr field's value into the log:
def handle(username: str, password: str) -> None:
    auth = UserAuth(username=username, password=password)
    logger.info(auth.dict())

# Silent — explicit field-level unmask, a different (obvious) mistake:
def handle(username: str, password: str) -> None:
    auth = UserAuth(username=username, password=password)
    logger.info(auth.password.get_secret_value())
```

# Citations

[1] agentsec checklist item `10-secret-str-serialized` (§10)
[2] OWASP:A02 (Cryptographic Failures)
[3] OWASP:A09 (Security Logging and Monitoring Failures)
[4] CWE-532 (Insertion of Sensitive Information into Log File)
