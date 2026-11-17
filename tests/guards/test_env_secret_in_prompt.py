from __future__ import annotations

from agentsec.guards.env_secret_in_prompt import EnvSecretInPromptGuard
from tests.guards._common import *  # noqa: F401,F403


def test_env_secret_in_prompt_flags_fstring_with_secret(tmp_path: Path) -> None:
    (tmp_path / "setup.py").write_text(
        "import os\n"
        "header = f\"Authorization: Bearer {os.environ.get('API_SECRET_KEY')}\"\n",
        encoding="utf-8",
    )
    findings = EnvSecretInPromptGuard().run(tmp_path, _llm_prof(tmp_path))
    rules = {f.rule for f in findings}
    assert "env-secret-in-prompt/secret-in-fstring" in rules

def test_env_secret_in_prompt_flags_getenv_in_fstring(tmp_path: Path) -> None:
    (tmp_path / "setup.py").write_text(
        "import os\n"
        "msg = f\"Use token: {os.getenv('API_TOKEN')}\"\n",
        encoding="utf-8",
    )
    findings = EnvSecretInPromptGuard().run(tmp_path, _llm_prof(tmp_path))
    rules = {f.rule for f in findings}
    assert "env-secret-in-prompt/secret-in-fstring" in rules

def test_env_secret_in_prompt_flags_password_env_in_fstring(tmp_path: Path) -> None:
    (tmp_path / "setup.py").write_text(
        "import os\n"
        "prompt = f\"DB connection: {os.environ.get('DATABASE_PASSWORD')}\"\n",
        encoding="utf-8",
    )
    findings = EnvSecretInPromptGuard().run(tmp_path, _llm_prof(tmp_path))
    assert findings

def test_env_secret_in_prompt_flags_bracket_access_in_fstring(tmp_path: Path) -> None:
    # Bracket/subscript access form (no `.get()` call) — the idiomatic way to read a
    # *required* secret, where a missing var should KeyError rather than silently pass None.
    # Structurally identical to the .get()/getenv() case for detection purposes: a same-line
    # env-secret-read co-occurring with an f-string open.
    (tmp_path / "setup.py").write_text(
        "import os\n"
        "header = f\"Bearer {os.environ['API_SECRET_KEY']}\"\n",
        encoding="utf-8",
    )
    findings = EnvSecretInPromptGuard().run(tmp_path, _llm_prof(tmp_path))
    rules = {f.rule for f in findings}
    assert "env-secret-in-prompt/secret-in-fstring" in rules

def test_env_secret_in_prompt_silent_for_bracket_access_substring_secret_words(tmp_path: Path) -> None:
    # FP-bait mirroring test_env_secret_in_prompt_silent_for_substring_secret_words, but for
    # the new bracket-access branch: the whole-segment `_SECRET_NAME` guard must hold there too.
    (tmp_path / "app.py").write_text(
        "import os\n"
        "a = f\"cap {os.environ['MAX_TOKENS']}\"\n"
        "b = f\"flag {os.environ['BYPASS_CACHE']}\"\n",
        encoding="utf-8",
    )
    assert EnvSecretInPromptGuard().run(tmp_path, _llm_prof(tmp_path)) == []

def test_env_secret_in_prompt_silent_for_secret_in_variable(tmp_path: Path) -> None:
    # Secret read into a variable — NOT inside f-string on same line; safe pattern.
    (tmp_path / "setup.py").write_text(
        "import os\n"
        "api_key = os.environ.get('OPENAI_API_KEY')\n"
        "prompt = f\"Answer this: {user_query}\"\n",
        encoding="utf-8",
    )
    assert EnvSecretInPromptGuard().run(tmp_path, _llm_prof(tmp_path)) == []

def test_env_secret_in_prompt_silent_for_sdk_auth_use(tmp_path: Path) -> None:
    # os.environ used for SDK auth, not in an f-string.
    (tmp_path / "client.py").write_text(
        "import os\n"
        "from openai import OpenAI\n"
        "client = OpenAI(api_key=os.environ.get('OPENAI_API_KEY'))\n",
        encoding="utf-8",
    )
    assert EnvSecretInPromptGuard().run(tmp_path, _llm_prof(tmp_path)) == []

def test_env_secret_in_prompt_silent_for_non_secret_env_in_fstring(tmp_path: Path) -> None:
    # f-string with env var that has a non-secret name — should not fire.
    (tmp_path / "app.py").write_text(
        "import os\n"
        "msg = f\"Running in env: {os.environ.get('APP_ENV')}\"\n",
        encoding="utf-8",
    )
    assert EnvSecretInPromptGuard().run(tmp_path, _llm_prof(tmp_path)) == []

def test_env_secret_in_prompt_pragma_silences(tmp_path: Path) -> None:
    (tmp_path / "setup.py").write_text(
        "# security: allow-secret-in-prompt\n"
        "import os\n"
        "header = f\"Bearer {os.environ.get('API_SECRET_KEY')}\"\n",
        encoding="utf-8",
    )
    assert EnvSecretInPromptGuard().run(tmp_path, _llm_prof(tmp_path)) == []

def test_env_secret_in_prompt_silent_for_substring_secret_words(tmp_path: Path) -> None:
    # #423 FP-bait: the secret word must be a whole `_`/`.`-delimited SEGMENT. TOKEN inside
    # MAX_TOKENS, PASS inside BYPASS_CACHE, and KEY inside MONKEY are NOT secrets.
    (tmp_path / "app.py").write_text(
        "import os\n"
        "a = f\"cap {os.getenv('MAX_TOKENS')}\"\n"
        "b = f\"flag {os.environ.get('BYPASS_CACHE')}\"\n"
        "c = f\"animal {os.getenv('MONKEY')}\"\n",
        encoding="utf-8",
    )
    assert EnvSecretInPromptGuard().run(tmp_path, _llm_prof(tmp_path)) == []

def test_env_secret_in_prompt_not_applicable_without_llm_feature() -> None:
    prof = mkprofile(Path("/tmp"), features={"python", "fastapi"})
    assert EnvSecretInPromptGuard().applies(prof) is False



def test_env_secret_in_prompt_matches_fused_and_plural_names(tmp_path: Path) -> None:
    # Regression (#445 review): the whole-segment rule that keeps TOKEN out of MAX_TOKENS also
    # missed the fused and plural spellings `SENDGRID_APIKEY` and `AWS_SECRETS`.
    # Each name gets its own tree, so a miss names the spelling that failed.
    for env in ("SENDGRID_APIKEY", "AWS_SECRETS", "APIKEY", "AWS_CREDS"):
        d = tmp_path / env.lower()
        d.mkdir()
        (d / "a.py").write_text(
            "import os\n"
            "def build(q):\n"
            f'    return f"v={{os.environ.get(\'{env}\')}} {{q}}"\n',
            encoding="utf-8",
        )
        assert len(EnvSecretInPromptGuard().run(d, _llm_prof(d))) == 1, env


def test_env_secret_in_prompt_still_ignores_non_secret_names(tmp_path: Path) -> None:
    # FP-bait, and the limit of the widening: `MAX_TOKENS` is structurally identical to
    # `AWS_SECRETS` (word + plural) and is ubiquitous in LLM code, so the plural is allowed only
    # for words whose plural is not itself a common non-secret term. `MONKEY` ends in KEY.
    for name, env in (("a.py", "MAX_TOKENS"), ("b.py", "BYPASS_CACHE"), ("c.py", "MONKEY")):
        (tmp_path / name).write_text(
            "import os\n"
            "def build(q):\n"
            f'    return f"v={{os.environ.get(\'{env}\')}} {{q}}"\n',
            encoding="utf-8",
        )
    assert EnvSecretInPromptGuard().run(tmp_path, _llm_prof(tmp_path)) == []


def test_env_secret_in_prompt_flags_camelcase_secret_names(tmp_path: Path) -> None:
    # #987 widening, reached through the shared `_SECRET_NAME`: a camelCase name whose secret
    # word is a capital-led segment fires here as it does in env-secret-logged. All three access
    # arms are covered. Each name gets its own tree, so a miss names the spelling that failed.
    for env, access in (
        ("dbPassword", "os.getenv('dbPassword')"),
        ("authToken", "os.environ.get('authToken')"),
        ("clientSecret", "os.environ['clientSecret']"),
        ("awsSecretKey", "os.getenv('awsSecretKey')"),
    ):
        d = tmp_path / env.lower()
        d.mkdir()
        (d / "a.py").write_text(
            "import os\n"
            "def build(q):\n"
            f'    return f"v={{{access}}} {{q}}"\n',
            encoding="utf-8",
        )
        findings = EnvSecretInPromptGuard().run(d, _llm_prof(d))
        assert len(findings) == 1, env
        assert findings[0].rule == "env-secret-in-prompt/secret-in-fstring", env


def test_env_secret_in_prompt_silent_for_camelcase_substring_lookalikes(tmp_path: Path) -> None:
    # FP-bait for the #987 camelCase widening, the four shapes env-secret-logged pins:
    # `maxTokens` (`Tokens` != `Token`), `bypassCache` (`bypass` != `pass`), `monkeyPatch`
    # (`monkey` != `key`), `authorName` (`author` != `auth`).
    for name, access in (
        ("a.py", "os.getenv('maxTokens')"),
        ("b.py", "os.environ.get('bypassCache')"),
        ("c.py", "os.environ['monkeyPatch']"),
        ("d.py", "os.getenv('authorName')"),
    ):
        (tmp_path / name).write_text(
            "import os\n"
            "def build(q):\n"
            f'    return f"v={{{access}}} {{q}}"\n',
            encoding="utf-8",
        )
    assert EnvSecretInPromptGuard().run(tmp_path, _llm_prof(tmp_path)) == []


# ── #425: one finding per offending line, not one per repo ─────────────────────────


def test_env_secret_in_prompt_reports_every_offending_line(tmp_path: Path) -> None:
    # Regression for #425: _check_secret_in_fstring returned its first hit from inside the
    # all-files loop, so N secrets interpolated into prompts reported 1, and an exception on
    # that one hid the rest. Two lines in one file plus one in another must give three.
    (tmp_path / "prompt_a.py").write_text(
        "import os\n"
        "header = f\"Bearer {os.environ.get('API_SECRET_KEY')}\"\n"
        "dsn = f\"postgres://app:{os.environ['DB_PASSWORD']}@db/app\"\n",
        encoding="utf-8",
    )
    (tmp_path / "prompt_b.py").write_text(
        "import os\n"
        "prompt = f\"Use token {os.getenv('GITHUB_TOKEN')} to answer\"\n",
        encoding="utf-8",
    )
    findings = EnvSecretInPromptGuard().run(tmp_path, _llm_prof(tmp_path))
    assert len(findings) == 3
    assert {f.location for f in findings} == {"prompt_a.py:2", "prompt_a.py:3", "prompt_b.py:2"}


def test_env_secret_in_prompt_benign_line_after_a_hit_stays_silent(tmp_path: Path) -> None:
    # FP-bait for the #425 widening: lines after the first hit used to be unreachable. A
    # non-secret env name in an f-string, a secret read into a variable, and SDK auth use,
    # all after a real hit in the same file, must not become extra findings.
    (tmp_path / "prompt.py").write_text(
        "import os\n"
        "header = f\"Bearer {os.environ.get('API_SECRET_KEY')}\"\n"
        "limit = f\"max={os.environ.get('MAX_TOKENS')}\"\n"
        "api_key = os.environ.get('OPENAI_API_KEY')\n"
        "client = OpenAI(api_key=os.getenv('OPENAI_API_KEY'))\n",
        encoding="utf-8",
    )
    findings = EnvSecretInPromptGuard().run(tmp_path, _llm_prof(tmp_path))
    assert [f.location for f in findings] == ["prompt.py:2"]


def test_env_secret_in_prompt_pragma_in_third_file_silences_all(tmp_path: Path) -> None:
    # The opt-out is repo-wide and must keep seeing every file after the #425 change.
    for name in ("prompt_a.py", "prompt_b.py"):
        (tmp_path / name).write_text(
            "import os\nheader = f\"Bearer {os.environ.get('API_SECRET_KEY')}\"\n",
            encoding="utf-8",
        )
    (tmp_path / "zz_settings.py").write_text("# security: allow-secret-in-prompt\n", encoding="utf-8")
    assert EnvSecretInPromptGuard().run(tmp_path, _llm_prof(tmp_path)) == []
