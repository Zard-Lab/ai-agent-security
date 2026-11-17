from __future__ import annotations

import pytest

from agentsec.guards.env_secret_console_log import EnvSecretConsoleLogGuard
from tests._timing import assert_growth
from tests.guards._common import *  # noqa: F401,F403


def test_env_secret_console_log_flags_dot_access(tmp_path: Path) -> None:
    (tmp_path / "config.js").write_text(
        "function debugConfig() {\n"
        "  console.log(process.env.STRIPE_SECRET_KEY);\n"
        "}\n",
        encoding="utf-8",
    )
    findings = EnvSecretConsoleLogGuard().run(tmp_path, _frontend_prof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "env-secret-console-log/direct-console-sink"
    assert findings[0].severity == "high"
    assert findings[0].location.endswith(":2")


def test_env_secret_console_log_flags_bracket_access(tmp_path: Path) -> None:
    (tmp_path / "config.ts").write_text(
        "export function debugConfig(): void {\n"
        "  console.error(process.env['DB_PASSWORD']);\n"
        "}\n",
        encoding="utf-8",
    )
    findings = EnvSecretConsoleLogGuard().run(tmp_path, _frontend_prof(tmp_path))
    assert len(findings) == 1


def test_env_secret_console_log_pragma_opt_out(tmp_path: Path) -> None:
    (tmp_path / "config.js").write_text(
        "console.log(process.env.STRIPE_SECRET_KEY); "
        "// security: allow-env-secret-console-log\n",
        encoding="utf-8",
    )
    assert EnvSecretConsoleLogGuard().run(tmp_path, _frontend_prof(tmp_path)) == []


def test_env_secret_console_log_silent_on_boolean_presence_check(tmp_path: Path) -> None:
    # FP-bait: a presence-only check via double-negation never leaks the secret value.
    (tmp_path / "config.js").write_text(
        "console.log(!!process.env.API_KEY);\n",
        encoding="utf-8",
    )
    assert EnvSecretConsoleLogGuard().run(tmp_path, _frontend_prof(tmp_path)) == []


def test_env_secret_console_log_silent_on_boolean_wrapper(tmp_path: Path) -> None:
    # FP-bait: Boolean(...) coercion — same presence-only reasoning.
    (tmp_path / "config.js").write_text(
        "console.log(Boolean(process.env.API_KEY));\n",
        encoding="utf-8",
    )
    assert EnvSecretConsoleLogGuard().run(tmp_path, _frontend_prof(tmp_path)) == []


def test_env_secret_console_log_silent_on_typeof_check(tmp_path: Path) -> None:
    # FP-bait: typeof reveals only the JS type ("string"/"undefined"), never the value.
    (tmp_path / "config.js").write_text(
        "console.log(typeof process.env.API_KEY);\n",
        encoding="utf-8",
    )
    assert EnvSecretConsoleLogGuard().run(tmp_path, _frontend_prof(tmp_path)) == []


def test_env_secret_console_log_silent_on_non_secret_env_var(tmp_path: Path) -> None:
    # FP-bait: a plain, non-secret env var (e.g. NODE_ENV) logged directly is fine.
    (tmp_path / "config.js").write_text(
        "console.log(process.env.NODE_ENV);\n",
        encoding="utf-8",
    )
    assert EnvSecretConsoleLogGuard().run(tmp_path, _frontend_prof(tmp_path)) == []


def test_env_secret_console_log_silent_two_line_alias_bypass(tmp_path: Path) -> None:
    # Documented false-negative scope: the env read and the console call are on
    # different lines — this guard's line-level heuristic does not follow dataflow.
    (tmp_path / "config.js").write_text(
        "const key = process.env.API_KEY;\n"
        "console.log('starting up');\n",
        encoding="utf-8",
    )
    assert EnvSecretConsoleLogGuard().run(tmp_path, _frontend_prof(tmp_path)) == []


def test_env_secret_console_log_silent_on_max_tokens_substring(tmp_path: Path) -> None:
    # Regression (PR #397 review #1): a secret word as a SUBSTRING of a non-secret env var
    # (TOKEN in MAX_TOKENS — a ubiquitous LLM config var — PASS in BYPASS_CACHE) stays silent.
    (tmp_path / "config.js").write_text(
        "console.log(process.env.MAX_TOKENS);\n"
        "console.log(process.env.NUM_TOKENS);\n"
        "console.log(process.env['BYPASS_CACHE']);\n",
        encoding="utf-8",
    )
    assert EnvSecretConsoleLogGuard().run(tmp_path, _frontend_prof(tmp_path)) == []


def test_env_secret_console_log_still_flags_real_token_secrets(tmp_path: Path) -> None:
    # The segment-anchoring must NOT drop real singular-`TOKEN` secrets.
    (tmp_path / "config.js").write_text(
        "console.log(process.env.GITHUB_TOKEN);\n"
        "console.log(process.env.AUTH_TOKEN);\n",
        encoding="utf-8",
    )
    assert len(EnvSecretConsoleLogGuard().run(tmp_path, _frontend_prof(tmp_path))) == 2


def test_env_secret_console_log_not_applicable_without_frontend_or_js() -> None:
    prof = mkprofile(Path("/tmp"), features={"python"})
    assert EnvSecretConsoleLogGuard().applies(prof) is False


def test_env_secret_console_log_silent_on_commented_example(tmp_path: Path) -> None:
    # FP-bait (#424): a commented-out console.log of an env secret must not fire.
    (tmp_path / "a.js").write_text(
        "// console.log(process.env.API_SECRET)\n"
        "const x = 1;\n",
        encoding="utf-8",
    )
    assert EnvSecretConsoleLogGuard().run(tmp_path, _frontend_prof(tmp_path)) == []


# ── #560: `_SECRET_NAME` is imported from env_secret_logged ──────────────────
#
# #445 widened the owner's `_SECRET_WORD` (APIKEYS?/SECRETS?/PASSWORDS?/CREDS?), but this
# guard kept its own narrow copy of the literal and stayed silent on every fused or plural
# name the Python sibling catches. It now imports the shared pattern. The Python tests
# only ever see a quoted key; the attribute arm here ends in a bare `\b`, so both arms are
# tested in both directions (review-doctrine Rule 1: a widening carries FP-bait).

def test_env_secret_console_log_flags_fused_and_plural_secret_names(tmp_path: Path) -> None:
    # The widening arm, in the attribute AND the bracket form. `SENDGRID_APIKEYS` pins the
    # `S?` on APIKEYS? (a mutation to `APIKEY` passed the owner's file before #445 finding 7).
    # `apiKey` is the camelCase spelling JS code actually uses.
    envs = ("SENDGRID_APIKEY", "SENDGRID_APIKEYS", "AWS_SECRETS", "AWS_CREDS", "DB_PASSWORDS", "apiKey")
    for i, env in enumerate(envs):
        for form, access in (("attr", f"process.env.{env}"), ("bracket", f"process.env['{env}']")):
            d = tmp_path / f"{form}{i}"
            d.mkdir()
            (d / "config.ts").write_text(
                f"export function debugConfig(): void {{\n  console.log({access});\n}}\n",
                encoding="utf-8",
            )
            findings = EnvSecretConsoleLogGuard().run(d, _frontend_prof(d))
            assert len(findings) == 1, (env, form)
            assert findings[0].rule == "env-secret-console-log/direct-console-sink"


def test_env_secret_console_log_silent_for_substring_and_plural_lookalikes(tmp_path: Path) -> None:
    # FP-bait for that widening, in the ATTRIBUTE form, which has no closing quote: only the
    # arm's trailing `\b` stops `MAX_TOKENS` matching on its `TOKEN` prefix. `MAX_TOKENS` is
    # word + plural, structurally identical to `AWS_SECRETS`; `MONKEY` ends in KEY;
    # `BYPASS_CACHE` contains PASS. The trailing `.toString()` pins the `\b` against the `.`
    # segment delimiter.
    (tmp_path / "config.js").write_text(
        "console.log(process.env.MAX_TOKENS);\n"
        "console.log(process.env.BYPASS_CACHE);\n"
        "console.log(process.env.MONKEY);\n"
        "console.log(process.env.MAX_TOKENS.toString());\n",
        encoding="utf-8",
    )
    assert EnvSecretConsoleLogGuard().run(tmp_path, _frontend_prof(tmp_path)) == []


# ── #987: camelCase secret names, in both the attribute and bracket forms ───────────────────

def test_env_secret_console_log_flags_camelcase_secret_names(tmp_path: Path) -> None:
    envs = ("dbPassword", "authToken", "clientSecret", "awsSecretKey")
    for i, env in enumerate(envs):
        for form, access in (("attr", f"process.env.{env}"), ("bracket", f"process.env['{env}']")):
            d = tmp_path / f"{form}{i}"
            d.mkdir()
            (d / "config.ts").write_text(
                f"export function debugConfig(): void {{\n  console.log({access});\n}}\n",
                encoding="utf-8",
            )
            findings = EnvSecretConsoleLogGuard().run(d, _frontend_prof(d))
            assert len(findings) == 1, (env, form)
            assert findings[0].rule == "env-secret-console-log/direct-console-sink"


def test_env_secret_console_log_silent_for_camelcase_substring_lookalikes(tmp_path: Path) -> None:
    # FP-bait, the same four camelCase shapes the Python sibling test pins.
    (tmp_path / "config.js").write_text(
        "console.log(process.env.maxTokens);\n"
        "console.log(process.env.bypassCache);\n"
        "console.log(process.env.monkeyPatch);\n"
        "console.log(process.env.authorName);\n",
        encoding="utf-8",
    )
    assert EnvSecretConsoleLogGuard().run(tmp_path, _frontend_prof(tmp_path)) == []


# ── #986: the shared `_SECRET_NAME` was quadratic on an unterminated secret-shaped run ───────

def _unterminated_js_tree(tmp_path: Path, n: int, segment: str, bracket: bool) -> Path:
    root = tmp_path / f"n{n}"
    root.mkdir()
    if bracket:
        # No closing quote/bracket: the attacker-reachable shape.
        body = f"console.log(process.env['{segment * n}\n"
    else:
        # The attribute arm has no closing delimiter at all — every character is attacker-
        # controlled up to end of line, so this is its own, always-"unterminated" shape.
        body = f"console.log(process.env.{segment * n}\n"
    (root / "config.js").write_text(body, encoding="utf-8")
    return root


@pytest.mark.slow
def test_env_secret_console_log_unterminated_bracket_camel_name_stays_linear(tmp_path: Path) -> None:
    sizes = [250, 1000, 4000, 16000]
    roots = {n: _unterminated_js_tree(tmp_path, n, "Key", bracket=True) for n in sizes}
    guard = EnvSecretConsoleLogGuard()

    def scan(n: int) -> None:
        guard.run(roots[n], _frontend_prof(roots[n]))

    assert_growth(scan, sizes, expected="linear")


@pytest.mark.slow
def test_env_secret_console_log_attribute_arm_camel_name_stays_linear(tmp_path: Path) -> None:
    sizes = [250, 1000, 4000, 16000]
    roots = {n: _unterminated_js_tree(tmp_path, n, "Key", bracket=False) for n in sizes}
    guard = EnvSecretConsoleLogGuard()

    def scan(n: int) -> None:
        guard.run(roots[n], _frontend_prof(roots[n]))

    assert_growth(scan, sizes, expected="linear")
