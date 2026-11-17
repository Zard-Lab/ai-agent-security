from __future__ import annotations

import pytest

from agentsec.guards.upstream_response_unvalidated import UpstreamResponseUnvalidatedGuard
from tests.guards._common import *  # noqa: F401,F403


def test_upstream_response_unvalidated_fires_chained_json(tmp_path: Path) -> None:
    (tmp_path / "client.py").write_text(
        "import requests\n\n"
        "def fetch(url: str):\n"
        "    return requests.get(url).json()\n",
        encoding="utf-8",
    )
    findings = UpstreamResponseUnvalidatedGuard().run(tmp_path, _pyprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "upstream-response-unvalidated/api-response-used-unvalidated"
    assert findings[0].severity == "high"

def test_upstream_response_unvalidated_fires_on_requests_chain_subscript(tmp_path: Path) -> None:
    (tmp_path / "client.py").write_text(
        "import requests\n"
        "def get_name():\n"
        "    return requests.get('https://api.example.com/u').json()['name']\n",
        encoding="utf-8",
    )
    findings = UpstreamResponseUnvalidatedGuard().run(tmp_path, _pyprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "upstream-response-unvalidated/api-response-used-unvalidated"

def test_upstream_response_unvalidated_ignores_inbound_request_json(tmp_path: Path) -> None:
    # The removed bare `.json()[` pattern matched inbound FastAPI request bodies (not an
    # upstream API response) — the guard's dominant FP. It must now stay silent.
    (tmp_path / "route.py").write_text(
        "async def handler(request):\n"
        "    return request.json()['amount']\n",
        encoding="utf-8",
    )
    assert UpstreamResponseUnvalidatedGuard().run(tmp_path, _pyprof(tmp_path)) == []

def test_upstream_response_unvalidated_silent_model_validate(tmp_path: Path) -> None:
    (tmp_path / "client.py").write_text(
        "import requests\n"
        "from pydantic import BaseModel\n\n"
        "class User(BaseModel):\n"
        "    name: str\n\n"
        "def fetch(url: str):\n"
        "    raw = requests.get(url).json()\n"
        "    return User.model_validate(raw)\n",
        encoding="utf-8",
    )
    assert UpstreamResponseUnvalidatedGuard().run(tmp_path, _pyprof(tmp_path)) == []

def test_upstream_response_unvalidated_pragma(tmp_path: Path) -> None:
    (tmp_path / "client.py").write_text(
        "# security: allow-unvalidated-upstream\n"
        "import requests\n\n"
        "def fetch(url: str):\n"
        "    return requests.get(url).json()\n",
        encoding="utf-8",
    )
    assert UpstreamResponseUnvalidatedGuard().run(tmp_path, _pyprof(tmp_path)) == []

def test_upstream_response_unvalidated_applies_gate() -> None:
    p = mkprofile(Path("."), features={"frontend"})
    assert not UpstreamResponseUnvalidatedGuard().applies(p)

def test_upstream_response_unvalidated_silent_when_validated_several_lines_later(tmp_path: Path) -> None:
    # the validation call sits well past the old next-line-only check but is still
    # inside the SAME enclosing function — the exact false-negative-avoidance shape
    # enclosing_function_span() adds. Before this fix, the padding below would have pushed the
    # validation call out of the (single-line) window and made the guard false-fire on
    # genuinely validated code.
    padding = "\n".join(f"    print({n})  # padding line {n}" for n in range(10))
    (tmp_path / "client.py").write_text(
        "import requests\n"
        "from pydantic import BaseModel\n\n"
        "class User(BaseModel):\n"
        "    name: str\n\n"
        "def fetch(url: str):\n"
        "    raw = requests.get(url).json()\n"
        f"{padding}\n"
        "    return User.model_validate(raw)\n",
        encoding="utf-8",
    )
    assert UpstreamResponseUnvalidatedGuard().run(tmp_path, _pyprof(tmp_path)) == []

def test_upstream_response_unvalidated_still_fires_when_dataflow_crosses_a_separate_function(
    tmp_path: Path,
) -> None:
    # False-negative scope, unchanged by the fix: a validation call that lives ONLY inside a
    # genuinely SEPARATE top-level helper function (not a same-function nested closure) is
    # still not detected — enclosing_function_span() only widens to fetch()'s OWN enclosing
    # body, not into functions it merely calls. A documented, narrow gap.
    (tmp_path / "client.py").write_text(
        "import requests\n"
        "from pydantic import BaseModel\n\n"
        "class User(BaseModel):\n"
        "    name: str\n\n"
        "def validate(raw):\n"
        "    return User.model_validate(raw)\n\n"
        "def fetch(url: str):\n"
        "    raw = requests.get(url).json()\n"
        "    return validate(raw)\n",
        encoding="utf-8",
    )
    findings = UpstreamResponseUnvalidatedGuard().run(tmp_path, _pyprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "upstream-response-unvalidated/api-response-used-unvalidated"

def test_upstream_response_unvalidated_module_level_call_uses_next_line_fallback(tmp_path: Path) -> None:
    # A chained .json() call with NO enclosing function (module-level script code) has no
    # enclosing function to widen to — must still fall back to checking only the next
    # non-blank line, not silently stop scanning.
    (tmp_path / "script.py").write_text(
        "import requests\n"
        "\n"
        "raw = requests.get('https://api.example.com').json()\n"
        "\n"
        "print('padding')\n"
        "User.model_validate(raw)\n",
        encoding="utf-8",
    )
    findings = UpstreamResponseUnvalidatedGuard().run(tmp_path, _pyprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "upstream-response-unvalidated/api-response-used-unvalidated"



def test_upstream_response_unvalidated_parses_only_when_anchor_present(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """issue #771: iter_functions runs only when a chained-.json() anchor is present.

    Counter installed on THIS guard's own module (the guard does ``from .base import
    iter_functions`` -- patching base would measure nothing; review-doctrine Rule 3). The
    anchor-present half proves the spy is wired to the parse path.
    """
    from agentsec.guards import upstream_response_unvalidated as mod

    calls = 0
    real = mod.iter_functions

    def spy(
        text: str, *, include_closures: bool = True, filename: str | Path = "<unknown>"
    ) -> list[tuple[int, str]]:
        nonlocal calls
        calls += 1
        return real(text, include_closures=include_closures, filename=filename)

    monkeypatch.setattr(mod, "iter_functions", spy)

    (tmp_path / "noanchor.py").write_text(
        "".join(f"def f{i}(x):\n    return x + {i}\n\n\n" for i in range(15)),
        encoding="utf-8",
    )
    profile = _pyprof(tmp_path)
    assert UpstreamResponseUnvalidatedGuard().run(tmp_path, profile) == []
    assert calls == 0

    (tmp_path / "client.py").write_text(
        "import requests\n"
        "def fetch(url):\n"
        "    return requests.get(url).json()\n",
        encoding="utf-8",
    )
    UpstreamResponseUnvalidatedGuard().run(tmp_path, profile)
    assert calls >= 1


# --- tool-function raw-external-return sinks -----------------------------------

def test_tool_raw_return_fires_on_http_text_content(tmp_path: Path) -> None:
    (tmp_path / "tools.py").write_text(
        "import requests\n"
        "from pydantic_ai import Agent\n\n"
        "agent = Agent('x')\n\n"
        "@agent.tool\n"
        "def fetch_page(ctx, url: str) -> str:\n"
        "    return requests.get(url).text\n",
        encoding="utf-8",
    )
    findings = UpstreamResponseUnvalidatedGuard().run(tmp_path, _pyprof(tmp_path))
    assert any(f.rule == "upstream-response-unvalidated/http-text-content-raw-return" for f in findings)


def test_tool_raw_return_fires_on_urllib(tmp_path: Path) -> None:
    (tmp_path / "tools.py").write_text(
        "import urllib.request\n"
        "from pydantic_ai import Agent\n\n"
        "agent = Agent('x')\n\n"
        "@agent.tool\n"
        "def fetch_page(ctx, url: str) -> str:\n"
        "    return urllib.request.urlopen(url).read()\n",
        encoding="utf-8",
    )
    findings = UpstreamResponseUnvalidatedGuard().run(tmp_path, _pyprof(tmp_path))
    assert any(f.rule == "upstream-response-unvalidated/urllib-raw-return" for f in findings)


def test_tool_raw_return_fires_on_file_read(tmp_path: Path) -> None:
    (tmp_path / "tools.py").write_text(
        "from pydantic_ai import Agent\n\n"
        "agent = Agent('x')\n\n"
        "@agent.tool\n"
        "def read_file(ctx, path: str) -> str:\n"
        "    return open(path).read()\n",
        encoding="utf-8",
    )
    findings = UpstreamResponseUnvalidatedGuard().run(tmp_path, _pyprof(tmp_path))
    assert any(f.rule == "upstream-response-unvalidated/file-raw-return" for f in findings)


def test_tool_raw_return_fires_on_subprocess_stdout(tmp_path: Path) -> None:
    (tmp_path / "tools.py").write_text(
        "import subprocess\n"
        "from pydantic_ai import Agent\n\n"
        "agent = Agent('x')\n\n"
        "@agent.tool\n"
        "def run_cmd(ctx, cmd: list[str]) -> str:\n"
        "    return subprocess.run(cmd, capture_output=True).stdout\n",
        encoding="utf-8",
    )
    findings = UpstreamResponseUnvalidatedGuard().run(tmp_path, _pyprof(tmp_path))
    assert any(f.rule == "upstream-response-unvalidated/subprocess-raw-return" for f in findings)


def test_tool_raw_return_fires_on_db_fetchall(tmp_path: Path) -> None:
    (tmp_path / "tools.py").write_text(
        "from pydantic_ai import Agent\n\n"
        "agent = Agent('x')\n\n"
        "@agent.tool\n"
        "def query_rows(ctx, cursor) -> list:\n"
        "    return cursor.fetchall()\n",
        encoding="utf-8",
    )
    findings = UpstreamResponseUnvalidatedGuard().run(tmp_path, _pyprof(tmp_path))
    assert any(f.rule == "upstream-response-unvalidated/db-raw-return" for f in findings)
    assert next(f for f in findings if f.rule == "upstream-response-unvalidated/db-raw-return").severity == "medium"


def test_tool_raw_return_silent_when_not_tool_decorated(tmp_path: Path) -> None:
    """FP-bait, the important one: the same raw-return shape inside an ORDINARY, undecorated
    helper function (routine backend I/O, not an LLM/agent tool) must not fire — the risk this
    rule targets only exists once the raw value becomes a tool's result."""
    (tmp_path / "helpers.py").write_text(
        "import requests\n\n"
        "def fetch_page(url: str) -> str:\n"
        "    return requests.get(url).text\n",
        encoding="utf-8",
    )
    findings = UpstreamResponseUnvalidatedGuard().run(tmp_path, _pyprof(tmp_path))
    assert not any(f.rule == "upstream-response-unvalidated/http-text-content-raw-return" for f in findings)


def test_tool_raw_return_silent_when_sanitized_forward(tmp_path: Path) -> None:
    """FP-bait: a sanitization call applied directly on the returned value silences the
    finding. The sink shapes above are single-line `return <call>(...)` returns, so the
    realistic mitigation wraps the return itself (H4, PR #1053 review) — a two-line
    assign-then-sanitize form never reaches the sink regex at all and would pass this test
    vacuously regardless of the sanitization gate."""
    (tmp_path / "tools.py").write_text(
        "import requests\n"
        "import html\n"
        "from pydantic_ai import Agent\n\n"
        "agent = Agent('x')\n\n"
        "@agent.tool\n"
        "def fetch_page(ctx, url: str) -> str:\n"
        "    return html.escape(requests.get(url).text)\n",
        encoding="utf-8",
    )
    findings = UpstreamResponseUnvalidatedGuard().run(tmp_path, _pyprof(tmp_path))
    assert not any(f.rule == "upstream-response-unvalidated/http-text-content-raw-return" for f in findings)


def test_tool_raw_return_fires_when_sanitizer_absent(tmp_path: Path) -> None:
    """Mutation anchor for the test above: the same single-line return shape, with no
    sanitizer, must still fire — proves the sanitized-forward bait is non-vacuous."""
    (tmp_path / "tools.py").write_text(
        "import requests\n"
        "from pydantic_ai import Agent\n\n"
        "agent = Agent('x')\n\n"
        "@agent.tool\n"
        "def fetch_page(ctx, url: str) -> str:\n"
        "    return requests.get(url).text\n",
        encoding="utf-8",
    )
    findings = UpstreamResponseUnvalidatedGuard().run(tmp_path, _pyprof(tmp_path))
    assert any(f.rule == "upstream-response-unvalidated/http-text-content-raw-return" for f in findings)


def _tool_return_findings(tmp_path: Path, ret: str) -> list[Finding]:
    (tmp_path / "tools.py").write_text(
        "import requests\n"
        "from pydantic_ai import Agent\n\n"
        "agent = Agent('x')\n\n"
        "@agent.tool\n"
        "def fetch(ctx, url: str, path: str) -> str:\n"
        f"    {ret}\n",
        encoding="utf-8",
    )
    return UpstreamResponseUnvalidatedGuard().run(tmp_path, _pyprof(tmp_path))


@pytest.mark.parametrize(("ret", "rule"), [
    ("return requests.get(url).text.strip()", "http-text-content-raw-return"),
    ("return open(path).read().strip()", "file-raw-return"),
])
def test_tool_raw_return_fires_when_only_whitespace_is_stripped(tmp_path: Path, ret: str, rule: str) -> None:
    """Round-2 review M2 (#1053): with the return line now inside the sanitizer scope, a bare
    `.strip()` there must not count as sanitization. Trimming whitespace leaves the content raw."""
    findings = _tool_return_findings(tmp_path, ret)
    assert any(f.rule == f"upstream-response-unvalidated/{rule}" for f in findings)


def test_tool_raw_return_silent_when_strip_tags_sanitizes(tmp_path: Path) -> None:
    """FP-bait for M2: a `strip_*` sanitizer (`strip_tags`) is still a sanitizer. Dropping the bare
    `.strip(` must not drop the `strip_`-prefixed names with it."""
    findings = _tool_return_findings(tmp_path, "return strip_tags(requests.get(url).text)")
    assert not any(f.rule == "upstream-response-unvalidated/http-text-content-raw-return" for f in findings)


def test_tool_raw_return_silent_at_module_level(tmp_path: Path) -> None:
    """FP-bait: a `return`-shaped raw-return line with no enclosing function at all (a
    syntax-error file — `return` is invalid outside a function body) must not crash the
    guard and must not fire, rather than erroring on a missing span. Exercises the matcher
    actually hitting the line (unlike an assignment, which never reaches the sink regex)."""
    (tmp_path / "broken.py").write_text(
        "import requests\n\n"
        "return requests.get('https://api.example.com').text\n",
        encoding="utf-8",
    )
    findings = UpstreamResponseUnvalidatedGuard().run(tmp_path, _pyprof(tmp_path))
    assert not any(f.rule == "upstream-response-unvalidated/http-text-content-raw-return" for f in findings)
