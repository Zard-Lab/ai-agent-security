from __future__ import annotations

import pytest

from agentsec.guards.langchain_load_prompt import LangchainLoadPromptGuard
from tests.guards._common import *  # noqa: F401,F403


def test_langchain_load_prompt_traversal_fires(tmp_path: Path) -> None:
    (tmp_path / "loader.py").write_text(
        "from langchain.prompts import load_prompt\n\n\n"
        "def get_prompt(template_name: str):\n"
        "    return load_prompt(template_name)\n",
        encoding="utf-8",
    )
    findings = LangchainLoadPromptGuard().run(tmp_path, _llm_prof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "langchain-load-prompt-traversal/dynamic-path"


def test_langchain_load_prompt_from_config_fires(tmp_path: Path) -> None:
    (tmp_path / "loader.py").write_text(
        "from langchain.prompts import load_prompt_from_config\n\n\n"
        "def get(cfg):\n"
        "    return load_prompt_from_config(cfg)\n",
        encoding="utf-8",
    )
    findings = LangchainLoadPromptGuard().run(tmp_path, _llm_prof(tmp_path))
    assert len(findings) == 1


def test_langchain_load_prompt_static_literal_passes(tmp_path: Path) -> None:
    (tmp_path / "loader.py").write_text(
        "from langchain.prompts import load_prompt\n\n\n"
        "def get():\n"
        '    return load_prompt("templates/system.yaml")\n',
        encoding="utf-8",
    )
    assert LangchainLoadPromptGuard().run(tmp_path, _llm_prof(tmp_path)) == []


def test_langchain_load_prompt_pragma_suppresses(tmp_path: Path) -> None:
    (tmp_path / "loader.py").write_text(
        "from langchain.prompts import load_prompt\n\n\n"
        "def get(name: str):\n"
        "    return load_prompt(name)  # security: allow-path-traversal\n",
        encoding="utf-8",
    )
    assert LangchainLoadPromptGuard().run(tmp_path, _llm_prof(tmp_path)) == []


def test_langchain_load_prompt_module_constant_passes(tmp_path: Path) -> None:
    # A trusted UPPER_SNAKE module constant is not user input — must not fire (FP fix).
    (tmp_path / "loader.py").write_text(
        "from langchain.prompts import load_prompt\n\n"
        'PROMPT_PATH = "templates/system.yaml"\n\n'
        "def get():\n"
        "    return load_prompt(PROMPT_PATH)\n",
        encoding="utf-8",
    )
    assert LangchainLoadPromptGuard().run(tmp_path, _llm_prof(tmp_path)) == []


def test_langchain_load_prompt_bare_resolve_still_fires(tmp_path: Path) -> None:
    # `.resolve()` alone is NOT a containment check — `user_path.resolve()` still escapes the
    # root — so a resolved-but-uncontained user path must still fire (soundness fix).
    (tmp_path / "loader.py").write_text(
        "from langchain.prompts import load_prompt\n\n\n"
        "def get(user_path):\n"
        "    return load_prompt(user_path.resolve())\n",
        encoding="utf-8",
    )
    assert len(LangchainLoadPromptGuard().run(tmp_path, _llm_prof(tmp_path))) == 1


def test_langchain_load_prompt_resolve_check_passes(tmp_path: Path) -> None:
    (tmp_path / "loader.py").write_text(
        "from langchain.prompts import load_prompt\n"
        "from pathlib import Path\n\n\n"
        "BASE = Path('templates')\n\n\n"
        "def get(name: str):\n"
        "    p = (BASE / name).resolve()\n"
        "    assert p.is_relative_to(BASE)\n"
        "    return load_prompt(p)\n",
        encoding="utf-8",
    )
    assert LangchainLoadPromptGuard().run(tmp_path, _llm_prof(tmp_path)) == []


def test_langchain_load_prompt_na_without_llm(tmp_path: Path) -> None:
    assert LangchainLoadPromptGuard().applies(mkprofile(tmp_path, features={"python"})) is False


def test_langchain_load_prompt_os_path_join_literals_passes(tmp_path: Path) -> None:
    # `os.path.join(<all literals>)` is a static path — must not fire (FP fix).
    (tmp_path / "loader.py").write_text(
        "import os\n"
        "from langchain.prompts import load_prompt\n\n\n"
        "def get():\n"
        '    return load_prompt(os.path.join("templates", "system.yaml"))\n',
        encoding="utf-8",
    )
    assert LangchainLoadPromptGuard().run(tmp_path, _llm_prof(tmp_path)) == []


def test_langchain_load_prompt_os_path_join_variable_fires(tmp_path: Path) -> None:
    # A variable segment makes the join dynamic — the carve-out must stay sound and still fire.
    (tmp_path / "loader.py").write_text(
        "import os\n"
        "from langchain.prompts import load_prompt\n\n\n"
        "def get(name: str):\n"
        '    return load_prompt(os.path.join("templates", name))\n',
        encoding="utf-8",
    )
    assert len(LangchainLoadPromptGuard().run(tmp_path, _llm_prof(tmp_path))) == 1


def test_langchain_load_prompt_config_attr_passes(tmp_path: Path) -> None:
    # A trusted config-object attribute is not user input — must not fire (FP fix).
    (tmp_path / "loader.py").write_text(
        "from langchain.prompts import load_prompt\n"
        "from app.config import settings\n\n\n"
        "def get():\n"
        "    return load_prompt(settings.template)\n",
        encoding="utf-8",
    )
    assert LangchainLoadPromptGuard().run(tmp_path, _llm_prof(tmp_path)) == []


def test_langchain_load_prompt_request_attr_fires(tmp_path: Path) -> None:
    # The config allowlist is NARROW — `request.*` is user-controlled and must still fire.
    (tmp_path / "loader.py").write_text(
        "from langchain.prompts import load_prompt\n\n\n"
        "def get(request):\n"
        "    return load_prompt(request.path)\n",
        encoding="utf-8",
    )
    assert len(LangchainLoadPromptGuard().run(tmp_path, _llm_prof(tmp_path))) == 1


def test_langchain_load_prompt_multiline_containment_guard_passes(tmp_path: Path) -> None:
    # A containment guard a few lines up (with a blank line between it and the call) must
    # suppress — the single-preceding-line check would miss this; the look-back window catches it.
    (tmp_path / "loader.py").write_text(
        "from langchain.prompts import load_prompt\n"
        "from pathlib import Path\n\n\n"
        "BASE = Path('templates')\n\n\n"
        "def get(name: str):\n"
        "    p = (BASE / name).resolve()\n"
        "    assert p.is_relative_to(BASE)\n"
        "\n"
        "    return load_prompt(p)\n",
        encoding="utf-8",
    )
    assert LangchainLoadPromptGuard().run(tmp_path, _llm_prof(tmp_path)) == []


def test_langchain_load_prompt_silent_on_docstring_example(tmp_path: Path) -> None:
    # FP-bait (#424): a dynamic load_prompt(path) EXAMPLE inside a docstring must not fire
    # (this guard's own module docstring self-matched on `load_prompt(path)`).
    (tmp_path / "p.py").write_text(
        '"""CVE-2026-34070 pattern:\n'
        "\n"
        "    prompt = load_prompt(user_supplied_path)\n"
        '"""\n'
        "from langchain.prompts.load import load_prompt\n",
        encoding="utf-8",
    )
    assert LangchainLoadPromptGuard().run(tmp_path, _llm_prof(tmp_path)) == []


def test_langchain_load_prompt_silent_when_guard_outside_old_fixed_lookback(tmp_path: Path) -> None:
    # the containment guard sits well past the old 4-line look-back but is still
    # inside the SAME function. Before this fix, the padding below would have pushed the guard
    # out of the window and made this false-fire on genuinely safe code.
    padding = "\n".join(f"    step_{n} = n\n" for n in range(10))
    (tmp_path / "p.py").write_text(
        "from langchain.prompts.load import load_prompt\n"
        "from pathlib import Path\n"
        "BASE = Path('/prompts')\n"
        "\n"
        "def get(name: str):\n"
        "    p = (BASE / name).resolve()\n"
        "    assert p.is_relative_to(BASE)\n"
        f"{padding}"
        "    return load_prompt(p)\n",
        encoding="utf-8",
    )
    assert LangchainLoadPromptGuard().run(tmp_path, _llm_prof(tmp_path)) == []


def test_langchain_load_prompt_still_fires_when_guard_is_after_the_call(tmp_path: Path) -> None:
    # Directionality regression guard: a containment check written AFTER the call has already
    # run doesn't mitigate it — the widened look-back must stay look-BACK only, never forward.
    (tmp_path / "p.py").write_text(
        "from langchain.prompts.load import load_prompt\n"
        "from pathlib import Path\n"
        "BASE = Path('/prompts')\n"
        "\n"
        "def get(name: str):\n"
        "    result = load_prompt(name)\n"
        "    p = (BASE / name).resolve()\n"
        "    assert p.is_relative_to(BASE)\n"
        "    return result\n",
        encoding="utf-8",
    )
    findings = LangchainLoadPromptGuard().run(tmp_path, _llm_prof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "langchain-load-prompt-traversal/dynamic-path"


# --- iac-open-ingress (§6c) ---------------------------------------------------


def test_langchain_load_prompt_parses_only_when_anchor_present(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """issue #771: iter_functions runs only when a load_prompt anchor is present.

    The counter is installed on THIS guard's own module namespace, because the guard does
    ``from .base import iter_functions`` -- patching ``agentsec.guards.base`` would measure
    nothing (review-doctrine Rule 3: a pin that always reads 0 is a failure that presents as
    success). The anchor-present half proves the spy is really wired to the parse path.
    """
    from agentsec.guards import langchain_load_prompt as mod

    calls = 0
    real = mod.iter_functions

    def spy(
        text: str, *, include_closures: bool = True, filename: str | Path = "<unknown>"
    ) -> list[tuple[int, str]]:
        nonlocal calls
        calls += 1
        return real(text, include_closures=include_closures, filename=filename)

    monkeypatch.setattr(mod, "iter_functions", spy)

    # (1) many-function file, NO load_prompt anchor -> zero parses, zero findings.
    (tmp_path / "noanchor.py").write_text(
        "".join(f"def f{i}(x):\n    return x + {i}\n\n\n" for i in range(15)),
        encoding="utf-8",
    )
    profile = _llm_prof(tmp_path)
    assert LangchainLoadPromptGuard().run(tmp_path, profile) == []
    assert calls == 0

    # (2) an anchor IS present -> the guard parses (lazily), proving the parse path is intact.
    (tmp_path / "loader.py").write_text(
        "from langchain.prompts import load_prompt\n"
        "def go(name):\n"
        "    return load_prompt(name)\n",
        encoding="utf-8",
    )
    LangchainLoadPromptGuard().run(tmp_path, profile)
    assert calls >= 1


def test_langchain_load_prompt_pragma_quoted_in_a_string_on_the_line_still_fires(tmp_path: Path) -> None:
    # The pragma phrase in a string on the flagged line is not a comment, so it must not suppress (#1040).
    def run(note: str) -> list:
        (tmp_path / "loader.py").write_text(
            "from langchain.prompts import load_prompt\n\n\n"
            "def get(name: str):\n"
            f'    p = load_prompt(name); _note = "{note}"\n'
            "    return p\n",
            encoding="utf-8",
        )
        return LangchainLoadPromptGuard().run(tmp_path, _llm_prof(tmp_path))

    assert len(run("neutral")) == 1
    findings = run("# security: allow-path-traversal")
    assert len(findings) == 1
    assert findings[0].location.endswith("loader.py:5")
