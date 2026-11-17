from __future__ import annotations

import pytest

from agentsec.guards.env_secret_logged import EnvSecretLoggedGuard
from tests._timing import assert_growth
from tests.guards._common import *  # noqa: F401,F403


def test_env_secret_logged_flags_getenv_in_logger(tmp_path: Path) -> None:
    (tmp_path / "h.py").write_text(
        "import logging\n"
        "import os\n"
        "logger = logging.getLogger(__name__)\n"
        "def connect():\n"
        "    logger.info(os.getenv('DB_PASSWORD'))\n",
        encoding="utf-8",
    )
    findings = EnvSecretLoggedGuard().run(tmp_path, _pyprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "env-secret-logged/direct-log-sink"
    assert findings[0].severity == "high"
    assert findings[0].location.endswith(":5")


def test_env_secret_logged_flags_environ_subscript_in_print(tmp_path: Path) -> None:
    (tmp_path / "h.py").write_text(
        "import os\n"
        "def connect():\n"
        "    print(os.environ['OPENAI_API_KEY'])\n",
        encoding="utf-8",
    )
    findings = EnvSecretLoggedGuard().run(tmp_path, _pyprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "env-secret-logged/direct-log-sink"


def test_env_secret_logged_flags_environ_get_method(tmp_path: Path) -> None:
    (tmp_path / "h.py").write_text(
        "import os\n"
        "import logging\n"
        "logger = logging.getLogger(__name__)\n"
        "def connect():\n"
        "    logger.warning(os.environ.get('STRIPE_SECRET_KEY'))\n",
        encoding="utf-8",
    )
    findings = EnvSecretLoggedGuard().run(tmp_path, _pyprof(tmp_path))
    assert len(findings) == 1


def test_env_secret_logged_pragma_opt_out(tmp_path: Path) -> None:
    (tmp_path / "h.py").write_text(
        "import os\n"
        "import logging\n"
        "logger = logging.getLogger(__name__)\n"
        "def connect():\n"
        "    logger.info(os.getenv('DB_PASSWORD'))  # security: allow-env-secret-logged\n",
        encoding="utf-8",
    )
    assert EnvSecretLoggedGuard().run(tmp_path, _pyprof(tmp_path)) == []


def test_env_secret_logged_silent_on_two_line_alias_bypass(tmp_path: Path) -> None:
    # Documented false-negative scope: the env read and the log call are on different
    # lines, so this guard's line-level heuristic does not follow the dataflow. This is
    # an intentional, honestly-documented gap (matches sibling guards' style), not caught
    # by design.
    (tmp_path / "h.py").write_text(
        "import os\n"
        "import logging\n"
        "logger = logging.getLogger(__name__)\n"
        "def connect():\n"
        "    password = os.getenv('DB_PASSWORD')\n"
        "    logger.info('connecting to db')\n",
        encoding="utf-8",
    )
    assert EnvSecretLoggedGuard().run(tmp_path, _pyprof(tmp_path)) == []


def test_env_secret_logged_silent_on_non_secret_env_var(tmp_path: Path) -> None:
    # FP-bait: a plain, non-secret env var (no KEY/SECRET/PASSWORD/... in the name)
    # logged directly must stay silent.
    (tmp_path / "h.py").write_text(
        "import os\n"
        "import logging\n"
        "logger = logging.getLogger(__name__)\n"
        "def show_env():\n"
        "    logger.info(os.getenv('APP_ENVIRONMENT'))\n",
        encoding="utf-8",
    )
    assert EnvSecretLoggedGuard().run(tmp_path, _pyprof(tmp_path)) == []


def test_env_secret_logged_silent_when_env_read_precedes_unrelated_log_call(tmp_path: Path) -> None:
    # FP-bait: an env-secret read on the same physical line but BEFORE an unrelated log
    # call (e.g. joined with a semicolon) must not fire — the read is not nested inside
    # the log call's arguments.
    (tmp_path / "h.py").write_text(
        "import os\n"
        "import logging\n"
        "logger = logging.getLogger(__name__)\n"
        "def connect():\n"
        "    key = os.getenv('API_KEY'); logger.info('connected')\n",
        encoding="utf-8",
    )
    assert EnvSecretLoggedGuard().run(tmp_path, _pyprof(tmp_path)) == []


def test_env_secret_logged_flags_bare_logging_module_call(tmp_path: Path) -> None:
    # Regression (PR #397 review #2): the module-level `logging.<level>(...)` convenience
    # function (no `logger = ` alias) is the shape the docstring claims to catch; it must fire.
    (tmp_path / "h.py").write_text(
        "import logging\n"
        "import os\n"
        "def connect():\n"
        "    logging.info(os.environ['OPENAI_API_KEY'])\n",
        encoding="utf-8",
    )
    findings = EnvSecretLoggedGuard().run(tmp_path, _pyprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].location.endswith(":4")


def test_env_secret_logged_silent_on_max_tokens_substring(tmp_path: Path) -> None:
    # Regression (PR #397 review #1): a secret word appearing only as a SUBSTRING of a
    # non-secret env var — TOKEN in MAX_TOKENS/NUM_TOKENS, PASS in BYPASS_CACHE, KEY in
    # MONKEY_MODE — must stay silent. These are ubiquitous non-secret config names.
    (tmp_path / "h.py").write_text(
        "import os\n"
        "import logging\n"
        "logger = logging.getLogger(__name__)\n"
        "def cfg():\n"
        "    logger.info(os.getenv('MAX_TOKENS'))\n"
        "    logger.info(os.getenv('NUM_TOKENS'))\n"
        "    logger.info(os.getenv('BYPASS_CACHE'))\n"
        "    logger.info(os.getenv('MONKEY_MODE'))\n",
        encoding="utf-8",
    )
    assert EnvSecretLoggedGuard().run(tmp_path, _pyprof(tmp_path)) == []


def test_env_secret_logged_still_flags_real_token_secrets(tmp_path: Path) -> None:
    # The segment-anchoring must NOT drop real singular-`TOKEN` secrets.
    (tmp_path / "h.py").write_text(
        "import os, logging\n"
        "logger = logging.getLogger(__name__)\n"
        "def cfg():\n"
        "    logger.info(os.getenv('GITHUB_TOKEN'))\n"
        "    logger.info(os.getenv('SECRET_KEY_BASE'))\n",
        encoding="utf-8",
    )
    assert len(EnvSecretLoggedGuard().run(tmp_path, _pyprof(tmp_path))) == 2


def test_env_secret_logged_silent_on_docstring_example(tmp_path: Path) -> None:
    # FP-bait (#424): the firing pattern appears only inside a triple-quoted docstring
    # (this guard's own module docstring carries exactly this example). strip_python_strings
    # blanks the docstring content, so it must not fire.
    (tmp_path / "h.py").write_text(
        '"""Anti-pattern this guard catches:\n'
        "\n"
        '    logger.info(os.getenv("DB_PASSWORD"))\n'
        '    print(os.environ["OPENAI_API_KEY"])\n'
        '"""\n'
        "import os\n"
        "import logging\n"
        "logger = logging.getLogger(__name__)\n",
        encoding="utf-8",
    )
    assert EnvSecretLoggedGuard().run(tmp_path, _pyprof(tmp_path)) == []


def test_env_secret_logged_not_applicable_without_python() -> None:
    prof = mkprofile(Path("/tmp"), features={"frontend"})
    assert EnvSecretLoggedGuard().applies(prof) is False


# ── #445: `_SECRET_WORD` lives here, so its widening is tested here ──────────
#
# PR #445 widened `_SECRET_WORD` (APIKEYS?/SECRETS?/PASSWORDS?/CREDS?) and shared
# `_SECRET_NAME` with env_secret_in_prompt. Both directions were covered only in that
# sibling's test file, leaving the OWNING guard with no test for its own change. Both
# arms below are required by review-doctrine Rule 1: a widening carries FP-bait, and the
# narrowing it sits on top of keeps its "still fires" case.

def test_env_secret_logged_flags_fused_and_plural_secret_names(tmp_path: Path) -> None:
    # The widening arm: fused (`APIKEY`) and plural (`SECRETS`, `CREDS`) spellings are real
    # secrets and the whole-segment rule alone missed them.
    # `SENDGRID_APIKEYS` pins the `S?` on APIKEYS? specifically: without it, mutating
    # `APIKEYS?` -> `APIKEY` passed the whole file (#445 gate, finding 7).
    for i, env in enumerate(
        ("SENDGRID_APIKEY", "SENDGRID_APIKEYS", "AWS_SECRETS", "AWS_CREDS", "DB_PASSWORDS")
    ):
        d = tmp_path / f"t{i}"
        d.mkdir()
        (d / "h.py").write_text(
            "import os\n"
            "import logging\n"
            "logger = logging.getLogger(__name__)\n"
            f"def connect():\n    logger.info(os.getenv('{env}'))\n",
            encoding="utf-8",
        )
        findings = EnvSecretLoggedGuard().run(d, _pyprof(d))
        assert len(findings) == 1, env
        assert findings[0].rule == "env-secret-logged/direct-log-sink"


def test_env_secret_logged_silent_for_substring_and_plural_lookalikes(tmp_path: Path) -> None:
    # FP-bait for that widening, and the reason it is spelled out rather than generalised:
    # `MAX_TOKENS` is structurally identical to `AWS_SECRETS` (word + plural) and is ubiquitous
    # in LLM code, `MONKEY` ends in KEY, `BYPASS_CACHE` contains PASS. None is a secret.
    (tmp_path / "h.py").write_text(
        "import os\n"
        "import logging\n"
        "logger = logging.getLogger(__name__)\n"
        "def setup():\n"
        "    logger.info(os.getenv('MAX_TOKENS'))\n"
        "    logger.info(os.environ.get('BYPASS_CACHE'))\n"
        "    logger.info(os.getenv('MONKEY'))\n",
        encoding="utf-8",
    )
    assert EnvSecretLoggedGuard().run(tmp_path, _pyprof(tmp_path)) == []


# ── #987: camelCase secret names (`dbPassword`, `authToken`, ...) ───────────────────────────

def test_env_secret_logged_flags_camelcase_secret_names(tmp_path: Path) -> None:
    # The widening arm: `re.IGNORECASE` erased the lower-to-upper camelCase boundary entirely,
    # so only `apiKey` ever matched (as one fused word already in `_SECRET_WORD`), never a
    # genuine camelCase segment like `Password`/`Token`/`Secret`.
    for i, env in enumerate(("dbPassword", "authToken", "clientSecret", "awsSecretKey")):
        d = tmp_path / f"t{i}"
        d.mkdir()
        (d / "h.py").write_text(
            "import os\n"
            "import logging\n"
            "logger = logging.getLogger(__name__)\n"
            f"def connect():\n    logger.info(os.getenv('{env}'))\n",
            encoding="utf-8",
        )
        findings = EnvSecretLoggedGuard().run(d, _pyprof(d))
        assert len(findings) == 1, env
        assert findings[0].rule == "env-secret-logged/direct-log-sink"


def test_env_secret_logged_silent_for_camelcase_substring_lookalikes(tmp_path: Path) -> None:
    # FP-bait for the camelCase widening, the same four shapes the snake-case rule already
    # pins, spelled in camelCase: `maxTokens` (`Tokens` != `Token`), `bypassCache` (`bypass` !=
    # `pass`), `monkeyPatch` (`monkey` != `key`), `authorName` (`author` != `auth`).
    (tmp_path / "h.py").write_text(
        "import os\n"
        "import logging\n"
        "logger = logging.getLogger(__name__)\n"
        "def setup():\n"
        "    logger.info(os.getenv('maxTokens'))\n"
        "    logger.info(os.environ.get('bypassCache'))\n"
        "    logger.info(os.getenv('monkeyPatch'))\n"
        "    logger.info(os.getenv('authorName'))\n",
        encoding="utf-8",
    )
    assert EnvSecretLoggedGuard().run(tmp_path, _pyprof(tmp_path)) == []


def test_env_secret_logged_camelcase_leading_lowercase_secret_word_is_a_known_miss(
    tmp_path: Path,
) -> None:
    # Pins the documented boundary of the #987 camel branch (see the `_CAMEL_SECRET_WORD` comment
    # in env_secret_logged.py): the camel secret word is capital-led only, so a secret word in
    # the LEADING lowercase segment never fires, while its snake twin does. That is a known miss
    # for `secretArn`/`tokenValue`/`authHeader`, and the reason `keyCount`/`passThrough` stay
    # silent where `KEY_COUNT`/`PASS_THROUGH` are snake-branch false positives. Admitting the
    # leading segment is a deliberate trade, so change this test only together with that comment.
    def fires(env: str) -> bool:
        d = tmp_path / f"t_{env}"
        d.mkdir()
        (d / "h.py").write_text(
            "import os\n"
            "import logging\n"
            "logger = logging.getLogger(__name__)\n"
            f"def connect():\n    logger.info(os.getenv('{env}'))\n",
            encoding="utf-8",
        )
        return bool(EnvSecretLoggedGuard().run(d, _pyprof(d)))

    for camel, snake in (
        ("secretArn", "SECRET_ARN"),
        ("tokenValue", "TOKEN_VALUE"),
        ("authHeader", "AUTH_HEADER"),
        ("keyCount", "KEY_COUNT"),
        ("passThrough", "PASS_THROUGH"),
    ):
        assert not fires(camel), camel
        assert fires(snake), snake


# ── #986: `_SECRET_NAME` was quadratic on an unterminated run of secret-word-shaped segments ──

def _unterminated_env_name_tree(tmp_path: Path, n: int, segment: str) -> Path:
    root = tmp_path / f"n{n}"
    root.mkdir()
    # No closing quote: the reachable hostile shape (issue #986). `segment` varies the run
    # shape between the snake (`KEY_`) and camel (`Ab`) branches of `_SECRET_NAME`.
    (root / "h.py").write_text(
        "import os\nimport logging\nlogger = logging.getLogger(__name__)\n"
        f"def leak():\n    logger.info(os.getenv(\"{segment * n}\n",
        encoding="utf-8",
    )
    return root


@pytest.mark.slow
def test_env_secret_logged_unterminated_snake_name_stays_linear(tmp_path: Path) -> None:
    sizes = [250, 1000, 4000, 16000]
    roots = {n: _unterminated_env_name_tree(tmp_path, n, "KEY_") for n in sizes}
    guard = EnvSecretLoggedGuard()

    def scan(n: int) -> None:
        guard.run(roots[n], _pyprof(roots[n]))

    assert_growth(scan, sizes, expected="linear")


@pytest.mark.slow
def test_env_secret_logged_unterminated_camel_name_stays_linear(tmp_path: Path) -> None:
    # `Key` (not e.g. `Ab`): the worst case needs the REPEATED unit to itself be a valid
    # `_CAMEL_SECRET_WORD` segment, so every repeat is an equally-valid candidate for "the"
    # secret-word instance — that ambiguity, not just "many segments", is what defeated a
    # bounded-but-non-atomic repeat count (measured ~24s at n=250, roughly CONSTANT rather
    # than growing, since the blowup comes from per-segment internal backtracking freedom
    # compounding across the ~20 bounded repeats, independent of how far n extends beyond that).
    sizes = [250, 1000, 4000, 16000]
    roots = {n: _unterminated_env_name_tree(tmp_path, n, "Key") for n in sizes}
    guard = EnvSecretLoggedGuard()

    def scan(n: int) -> None:
        guard.run(roots[n], _pyprof(roots[n]))

    assert_growth(scan, sizes, expected="linear")
