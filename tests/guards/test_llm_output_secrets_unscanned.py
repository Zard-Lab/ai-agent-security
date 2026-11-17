"""Tests for the llm-output-secrets-unscanned guard.

Covers:
  - llm-output-secrets-unscanned/no-secret-scan-before-persist (HIGH)
"""
from __future__ import annotations

from agentsec.guards.llm_output_secrets_unscanned import LlmOutputSecretsUnscannedGuard
from tests.guards._common import *  # noqa: F401,F403

_RULE = "llm-output-secrets-unscanned/no-secret-scan-before-persist"


def _guard() -> LlmOutputSecretsUnscannedGuard:
    return LlmOutputSecretsUnscannedGuard()


# ---------------------------------------------------------------------------
# applies() gate
# ---------------------------------------------------------------------------

def test_applies_when_llm_feature_present() -> None:
    prof = mkprofile(Path("/tmp"), features={"llm", "python"})
    assert _guard().applies(prof) is True


def test_not_applies_without_llm_feature() -> None:
    prof = mkprofile(Path("/tmp"), features={"fastapi", "python"})
    assert _guard().applies(prof) is False


# ---------------------------------------------------------------------------
# planted violations — fires
# ---------------------------------------------------------------------------

def test_fires_on_file_write_with_no_scan(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "def sync_notes(prompt):\n"
        "    response = llm_client.invoke(prompt)\n"
        '    with open("notes.md", "w") as f:\n'
        "        f.write(response.content)\n",
        encoding="utf-8",
    )
    findings = _guard().run(tmp_path, _llm_prof(tmp_path))
    assert [f.rule for f in findings] == [_RULE]
    assert findings[0].severity == "high"


def test_fires_on_inline_open_write(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "def sync_notes(prompt):\n"
        "    response = llm_client.invoke(prompt)\n"
        '    open("notes.md", "w").write(response.content)\n',
        encoding="utf-8",
    )
    findings = _guard().run(tmp_path, _llm_prof(tmp_path))
    assert [f.rule for f in findings] == [_RULE]


def test_fires_on_derived_variable_written(tmp_path: Path) -> None:
    # "or something derived from it" — a one-hop pass-through variable still counts.
    (tmp_path / "app.py").write_text(
        "def sync_notes(prompt):\n"
        "    response = llm_client.invoke(prompt)\n"
        "    content = response.text\n"
        '    with open("out.txt", "w") as f:\n'
        "        f.write(content)\n",
        encoding="utf-8",
    )
    findings = _guard().run(tmp_path, _llm_prof(tmp_path))
    assert [f.rule for f in findings] == [_RULE]


def test_fires_on_git_commit_subprocess_sink(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "def publish(prompt):\n"
        "    summary = llm_client.invoke(prompt)\n"
        '    with open("CHANGELOG.md", "w") as f:\n'
        "        f.write(summary.content)\n"
        "    subprocess.run(\n"
        '        ["git", "commit", "-m", "auto-update"],\n'
        "        check=True,\n"
        "    )\n",
        encoding="utf-8",
    )
    rules = {f.rule for f in _guard().run(tmp_path, _llm_prof(tmp_path))}
    assert _RULE in rules


def test_fires_on_gitpython_commit_sink(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "def publish(prompt):\n"
        "    summary = llm_client.invoke(prompt)\n"
        '    with open("CHANGELOG.md", "w") as f:\n'
        "        f.write(summary.content)\n"
        "    repo.index.commit('auto-update')\n",
        encoding="utf-8",
    )
    rules = {f.rule for f in _guard().run(tmp_path, _llm_prof(tmp_path))}
    assert _RULE in rules


def test_fires_on_await_llm_call(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "async def sync_notes(prompt):\n"
        "    response = await client.ainvoke(prompt)\n"
        '    with open("notes.md", "w") as f:\n'
        "        f.write(response.content)\n",
        encoding="utf-8",
    )
    findings = _guard().run(tmp_path, _llm_prof(tmp_path))
    assert [f.rule for f in findings] == [_RULE]


def test_fires_on_create_when_llm_sdk_imported(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "import openai\n"
        "def sync_notes(prompt):\n"
        "    response = openai.chat.completions.create(messages=[prompt])\n"
        '    with open("notes.md", "w") as f:\n'
        "        f.write(response.choices[0].message.content)\n",
        encoding="utf-8",
    )
    findings = _guard().run(tmp_path, _llm_prof(tmp_path))
    assert [f.rule for f in findings] == [_RULE]


# ---------------------------------------------------------------------------
# FP-bait — stays silent
# ---------------------------------------------------------------------------

def test_fp_bait_detect_secrets_scan_between_generation_and_write(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "def sync_notes(prompt):\n"
        "    response = llm_client.invoke(prompt)\n"
        "    findings = detect_secrets.scan_string(response.content)\n"
        "    if findings:\n"
        "        raise ValueError('secret detected')\n"
        '    with open("notes.md", "w") as f:\n'
        "        f.write(response.content)\n",
        encoding="utf-8",
    )
    findings = _guard().run(tmp_path, _llm_prof(tmp_path))
    assert _RULE not in {f.rule for f in findings}


def test_fp_bait_gitleaks_scan_between_generation_and_commit(tmp_path: Path) -> None:
    # The scan runs BEFORE either sink, so it protects both the write and the commit.
    (tmp_path / "app.py").write_text(
        "def publish(prompt):\n"
        "    summary = llm_client.invoke(prompt)\n"
        "    subprocess.run(['gitleaks', 'detect', '--no-git', '-s', '-'],\n"
        "                   input=summary.content, check=True)\n"
        '    with open("CHANGELOG.md", "w") as f:\n'
        "        f.write(summary.content)\n"
        "    repo.index.commit('auto-update')\n",
        encoding="utf-8",
    )
    findings = _guard().run(tmp_path, _llm_prof(tmp_path))
    assert _RULE not in {f.rule for f in findings}


def test_fp_bait_bandit_scan_silences(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "def sync_notes(prompt):\n"
        "    response = llm_client.invoke(prompt)\n"
        "    subprocess.run(['bandit', '-r', '.'], check=True)\n"
        '    with open("notes.md", "w") as f:\n'
        "        f.write(response.content)\n",
        encoding="utf-8",
    )
    findings = _guard().run(tmp_path, _llm_prof(tmp_path))
    assert _RULE not in {f.rule for f in findings}


def test_fp_bait_no_sink_reached(tmp_path: Path) -> None:
    # LLM output that never reaches a file-write/commit sink — just logged/returned — stays silent.
    (tmp_path / "app.py").write_text(
        "def summarize(prompt):\n"
        "    response = llm_client.invoke(prompt)\n"
        "    logger.info(response.content)\n"
        "    return response.content\n",
        encoding="utf-8",
    )
    findings = _guard().run(tmp_path, _llm_prof(tmp_path))
    assert _RULE not in {f.rule for f in findings}


def test_fp_bait_write_unrelated_to_llm_output(tmp_path: Path) -> None:
    # A file write in a function that also happens to call an LLM, but the written value has no
    # relationship to the LLM result, must not fire.
    (tmp_path / "app.py").write_text(
        "def sync_notes(prompt, static_header):\n"
        "    response = llm_client.invoke(prompt)\n"
        '    with open("header.txt", "w") as f:\n'
        "        f.write(static_header)\n",
        encoding="utf-8",
    )
    findings = _guard().run(tmp_path, _llm_prof(tmp_path))
    assert _RULE not in {f.rule for f in findings}


def test_fp_bait_write_handle_not_from_open(tmp_path: Path) -> None:
    # `.write(...)` on a name never bound via `open(...)` (e.g. a socket, a StringIO passed in) is
    # not treated as a file-write sink.
    (tmp_path / "app.py").write_text(
        "def stream(prompt, sock):\n"
        "    response = llm_client.invoke(prompt)\n"
        "    sock.write(response.content)\n",
        encoding="utf-8",
    )
    findings = _guard().run(tmp_path, _llm_prof(tmp_path))
    assert _RULE not in {f.rule for f in findings}


def test_fp_bait_create_on_non_llm_sdk(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "import stripe\n"
        "def sync_notes(prompt):\n"
        "    response = stripe.Charge.create(amount=1)\n"
        '    with open("notes.md", "w") as f:\n'
        "        f.write(response.body)\n",
        encoding="utf-8",
    )
    findings = _guard().run(tmp_path, _llm_prof(tmp_path))
    assert _RULE not in {f.rule for f in findings}


def test_fp_bait_same_named_var_in_another_function(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "def ask(prompt):\n"
        "    response = llm.invoke(prompt)\n"
        "    return response\n"
        "\n"
        "def save_upload(req):\n"
        "    response = requests.post(url, json=req)\n"
        '    with open("upload.bin", "w") as f:\n'
        "        f.write(response.text)\n",
        encoding="utf-8",
    )
    findings = _guard().run(tmp_path, _llm_prof(tmp_path))
    assert _RULE not in {f.rule for f in findings}


def test_fp_bait_scan_only_after_the_sink_does_not_count(tmp_path: Path) -> None:
    # A scan call AFTER the persist sink does not retroactively protect it — the scan must sit
    # BETWEEN generation and the sink to count.
    (tmp_path / "app.py").write_text(
        "def sync_notes(prompt):\n"
        "    response = llm_client.invoke(prompt)\n"
        '    with open("notes.md", "w") as f:\n'
        "        f.write(response.content)\n"
        "    detect_secrets.scan_string(response.content)\n",
        encoding="utf-8",
    )
    findings = _guard().run(tmp_path, _llm_prof(tmp_path))
    assert [f.rule for f in findings] == [_RULE]


def test_fp_bait_when_pragma_present(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "# security: allow-llm-output-secrets-unscanned\n"
        "def sync_notes(prompt):\n"
        "    response = llm_client.invoke(prompt)\n"
        '    with open("notes.md", "w") as f:\n'
        "        f.write(response.content)\n",
        encoding="utf-8",
    )
    findings = _guard().run(tmp_path, _llm_prof(tmp_path))
    assert findings == []


def test_reports_every_violation_across_files(tmp_path: Path) -> None:
    violation = (
        "def sync_notes(prompt):\n"
        "    response = llm_client.invoke(prompt)\n"
        '    with open("notes.md", "w") as f:\n'
        "        f.write(response.content)\n"
    )
    (tmp_path / "service_a.py").write_text(violation, encoding="utf-8")
    (tmp_path / "service_b.py").write_text(violation, encoding="utf-8")
    findings = _guard().run(tmp_path, _llm_prof(tmp_path))
    assert [f.rule for f in findings] == [_RULE] * 2
    assert {f.location.split(":")[0] for f in findings} == {"service_a.py", "service_b.py"}
