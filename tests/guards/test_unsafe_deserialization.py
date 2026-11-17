from __future__ import annotations

from agentsec.findings import Finding
from agentsec.guards.unsafe_deserialization import UnsafeDeserializationGuard
from tests._timing import TimingBudget, assert_within, register
from tests.guards._common import *  # noqa: F401,F403


def test_unsafe_deserialization_flags_pickle_loads(tmp_path: Path) -> None:
    (tmp_path / "c.py").write_text("import pickle\ndef load(b):\n    return pickle.loads(b)\n", encoding="utf-8")
    findings = UnsafeDeserializationGuard().run(tmp_path, _pyprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "unsafe-deserialization/untrusted-load"
    assert findings[0].severity == "critical"

def test_unsafe_deserialization_flags_yaml_and_torch(tmp_path: Path) -> None:
    (tmp_path / "a.py").write_text("import yaml\nyaml.load(open('x').read())\n", encoding="utf-8")
    (tmp_path / "b.py").write_text("import torch\ntorch.load('m.pt')\n", encoding="utf-8")
    assert len(UnsafeDeserializationGuard().run(tmp_path, _pyprof(tmp_path))) == 2

def test_unsafe_deserialization_passes_safe_variants(tmp_path: Path) -> None:
    (tmp_path / "a.py").write_text(
        "import yaml\nyaml.safe_load(s)\nyaml.load(s, Loader=yaml.SafeLoader)\n", encoding="utf-8"
    )
    (tmp_path / "b.py").write_text("import torch\ntorch.load('m.pt', weights_only=True)\n", encoding="utf-8")
    assert UnsafeDeserializationGuard().run(tmp_path, _pyprof(tmp_path)) == []

def test_unsafe_deserialization_passes_json(tmp_path: Path) -> None:
    (tmp_path / "c.py").write_text("import json\ndef load(s):\n    return json.loads(s)\n", encoding="utf-8")
    assert UnsafeDeserializationGuard().run(tmp_path, _pyprof(tmp_path)) == []

def test_unsafe_deserialization_pragma(tmp_path: Path) -> None:
    (tmp_path / "c.py").write_text(
        "import pickle\ndef load(b):\n    return pickle.loads(b)  # security: allow-unsafe-deserialize\n", encoding="utf-8"
    )
    assert UnsafeDeserializationGuard().run(tmp_path, _pyprof(tmp_path)) == []

def test_unsafe_deserialization_na_without_python() -> None:
    assert UnsafeDeserializationGuard().applies(mkprofile(Path("/tmp"), features={"frontend"})) is False


def test_unsafe_deserialization_flags_trust_remote_code(tmp_path: Path) -> None:
    (tmp_path / "m.py").write_text(
        "from transformers import AutoModelForCausalLM\n"
        'model = AutoModelForCausalLM.from_pretrained(model_id, trust_remote_code=True, torch_dtype=torch.float16)\n',
        encoding="utf-8",
    )
    findings = UnsafeDeserializationGuard().run(tmp_path, _pyprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "unsafe-deserialization/trust-remote-code-rce"
    assert findings[0].severity == "critical"


def test_unsafe_deserialization_passes_from_pretrained_no_trust_remote_code(tmp_path: Path) -> None:
    (tmp_path / "m.py").write_text(
        "from transformers import AutoModel\n"
        'model = AutoModel.from_pretrained("bert-base-uncased")\n',
        encoding="utf-8",
    )
    assert UnsafeDeserializationGuard().run(tmp_path, _pyprof(tmp_path)) == []


def test_unsafe_deserialization_passes_from_pretrained_trust_remote_code_false(tmp_path: Path) -> None:
    (tmp_path / "m.py").write_text(
        "from transformers import AutoModel\n"
        'model = AutoModel.from_pretrained("some/model", trust_remote_code=False)\n',
        encoding="utf-8",
    )
    assert UnsafeDeserializationGuard().run(tmp_path, _pyprof(tmp_path)) == []


def test_unsafe_deserialization_flags_trust_remote_code_multiline(tmp_path: Path) -> None:
    # The dominant real-world style: one kwarg per line. Whole-file matching must catch it
    # and report the call's opening line, not silently miss it (line-by-line FN).
    (tmp_path / "m.py").write_text(
        "from transformers import AutoModelForCausalLM\n"
        "model = AutoModelForCausalLM.from_pretrained(\n"
        '    "org/model",\n'
        "    trust_remote_code=True,\n"
        "    torch_dtype=torch.float16,\n"
        ")\n",
        encoding="utf-8",
    )
    findings = UnsafeDeserializationGuard().run(tmp_path, _pyprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "unsafe-deserialization/trust-remote-code-rce"
    assert findings[0].location.endswith(":2")  # reported at the from_pretrained( line


def test_unsafe_deserialization_flags_trust_remote_code_nested_call_arg(tmp_path: Path) -> None:
    # A nested call in the positional args must not stop the match at its inner `)`.
    (tmp_path / "m.py").write_text(
        "from transformers import AutoModel\n"
        "model = AutoModel.from_pretrained(resolve_model_id(), trust_remote_code=True)\n",
        encoding="utf-8",
    )
    findings = UnsafeDeserializationGuard().run(tmp_path, _pyprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "unsafe-deserialization/trust-remote-code-rce"


def test_unsafe_deserialization_trust_remote_code_pragma_on_kwarg_line(tmp_path: Path) -> None:
    # Multi-line call with the pragma trailing the trust_remote_code line — must suppress.
    (tmp_path / "m.py").write_text(
        "from transformers import AutoModel\n"
        "model = AutoModel.from_pretrained(\n"
        '    "org/model",\n'
        "    trust_remote_code=True,  # security: allow-unsafe-deserialize\n"
        ")\n",
        encoding="utf-8",
    )
    assert UnsafeDeserializationGuard().run(tmp_path, _pyprof(tmp_path)) == []


def test_unsafe_deserialization_flags_haystack_pipeline_load(tmp_path: Path) -> None:
    (tmp_path / "p.py").write_text(
        "from haystack import Pipeline\n"
        "def load_pipeline(config: str):\n"
        "    return Pipeline.loads(config)\n",
        encoding="utf-8",
    )
    findings = UnsafeDeserializationGuard().run(tmp_path, _pyprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "unsafe-deserialization/haystack-pipeline-load"
    assert findings[0].severity == "critical"


def test_unsafe_deserialization_flags_haystack_pipeline_load_from_yaml(tmp_path: Path) -> None:
    (tmp_path / "p.py").write_text(
        "from haystack import Pipeline\n"
        "pipeline = Pipeline.load_from_yaml(uploaded_path)\n",
        encoding="utf-8",
    )
    findings = UnsafeDeserializationGuard().run(tmp_path, _pyprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "unsafe-deserialization/haystack-pipeline-load"


def test_unsafe_deserialization_silent_on_unrelated_pipeline_load(tmp_path: Path) -> None:
    # FP-bait: a differently-shaped object's .load() (not the Pipeline class) must not fire.
    (tmp_path / "p.py").write_text(
        "config = my_settings_loader.load()\n",
        encoding="utf-8",
    )
    assert UnsafeDeserializationGuard().run(tmp_path, _pyprof(tmp_path)) == []


def test_unsafe_deserialization_silent_on_non_haystack_pipeline(tmp_path: Path) -> None:
    # FP-bait for the collision case (#306 review): a custom `Pipeline` class with a `load()`
    # method, in a file that does NOT import haystack, must not fire — `Pipeline` is a common
    # class name (sklearn/spaCy/Kedro/ETL). The rule is scoped to files that import haystack.
    (tmp_path / "p.py").write_text(
        "class Pipeline:\n"
        "    @classmethod\n"
        "    def load(cls, path: str) -> 'Pipeline': ...\n"
        "p = Pipeline.load('config.json')\n",
        encoding="utf-8",
    )
    assert UnsafeDeserializationGuard().run(tmp_path, _pyprof(tmp_path)) == []


def test_unsafe_deserialization_haystack_pipeline_pragma(tmp_path: Path) -> None:
    (tmp_path / "p.py").write_text(
        "from haystack import Pipeline\n"
        "def load_pipeline(config: str):\n"
        "    return Pipeline.loads(config)  # security: allow-unsafe-deserialize\n",
        encoding="utf-8",
    )
    assert UnsafeDeserializationGuard().run(tmp_path, _pyprof(tmp_path)) == []


# --- JS/Node (js-yaml unsafe schema) --------------------------------------------


def test_unsafe_deserialization_applies_for_js_without_python() -> None:
    assert UnsafeDeserializationGuard().applies(
        mkprofile(Path("/tmp"), features={"javascript"})
    ) is True
    assert UnsafeDeserializationGuard().applies(
        mkprofile(Path("/tmp"), features={"typescript"})
    ) is True


def test_unsafe_deserialization_flags_js_yaml_load_default_full_schema(tmp_path: Path) -> None:
    (tmp_path / "load.js").write_text(
        "const yaml = require('js-yaml');\n"
        "const data = yaml.load(input, { schema: DEFAULT_FULL_SCHEMA });\n",
        encoding="utf-8",
    )
    findings = UnsafeDeserializationGuard().run(tmp_path, mkprofile(tmp_path, features={"javascript"}))
    assert len(findings) == 1
    assert findings[0].rule == "unsafe-deserialization/js-yaml-unsafe-schema"
    assert findings[0].severity == "critical"
    assert findings[0].location.endswith(":2")


def test_unsafe_deserialization_passes_js_yaml_load_no_schema(tmp_path: Path) -> None:
    # No schema option — js-yaml's own default (safe in v4+) applies. Must stay silent.
    (tmp_path / "load.js").write_text(
        "const yaml = require('js-yaml');\n"
        "const data = yaml.load(input);\n",
        encoding="utf-8",
    )
    assert UnsafeDeserializationGuard().run(tmp_path, mkprofile(tmp_path, features={"javascript"})) == []


def test_unsafe_deserialization_passes_js_yaml_safeload_no_schema(tmp_path: Path) -> None:
    # safeLoad with no schema override is the always-safe function. Must stay silent.
    (tmp_path / "load.js").write_text(
        "const yaml = require('js-yaml');\n"
        "const data = yaml.safeLoad(input);\n",
        encoding="utf-8",
    )
    assert UnsafeDeserializationGuard().run(tmp_path, mkprofile(tmp_path, features={"javascript"})) == []


def test_unsafe_deserialization_flags_js_yaml_loadall_default_full_schema(tmp_path: Path) -> None:
    (tmp_path / "load.ts").write_text(
        "import yaml from 'js-yaml';\n"
        "yaml.loadAll(input, (doc) => docs.push(doc), { schema: DEFAULT_FULL_SCHEMA });\n",
        encoding="utf-8",
    )
    findings = UnsafeDeserializationGuard().run(tmp_path, mkprofile(tmp_path, features={"typescript"}))
    assert len(findings) == 1
    assert findings[0].rule == "unsafe-deserialization/js-yaml-unsafe-schema"


def test_unsafe_deserialization_flags_js_yaml_safeload_dangerous_schema_override(tmp_path: Path) -> None:
    # safeLoad's default schema can be OVERRIDDEN by an explicit `schema:` option — the CodeQL
    # finding this guard exists for (safe-by-name is not safe-by-construction).
    (tmp_path / "load.js").write_text(
        "const yaml = require('js-yaml');\n"
        "const data = yaml.safeLoad(input, { schema: DEFAULT_FULL_SCHEMA });\n",
        encoding="utf-8",
    )
    findings = UnsafeDeserializationGuard().run(tmp_path, mkprofile(tmp_path, features={"javascript"}))
    assert len(findings) == 1
    assert findings[0].rule == "unsafe-deserialization/js-yaml-unsafe-schema"


def test_unsafe_deserialization_flags_js_yaml_js_types_schema(tmp_path: Path) -> None:
    (tmp_path / "load.js").write_text(
        "const yaml = require('js-yaml');\n"
        "const { all } = require('js-yaml-js-types');\n"
        "const data = yaml.load(input, { schema: all });\n",
        encoding="utf-8",
    )
    findings = UnsafeDeserializationGuard().run(tmp_path, mkprofile(tmp_path, features={"javascript"}))
    assert len(findings) == 1
    assert findings[0].rule == "unsafe-deserialization/js-yaml-unsafe-schema"


def test_unsafe_deserialization_flags_js_yaml_extend_full_schema(tmp_path: Path) -> None:
    # `.extend()` on the DANGEROUS base (DEFAULT_FULL_SCHEMA) — the genuinely unsafe extend shape.
    (tmp_path / "load.js").write_text(
        "const yaml = require('js-yaml');\n"
        "const data = yaml.load(input, { schema: yaml.DEFAULT_FULL_SCHEMA.extend([customType]) });\n",
        encoding="utf-8",
    )
    findings = UnsafeDeserializationGuard().run(tmp_path, mkprofile(tmp_path, features={"javascript"}))
    assert len(findings) == 1
    assert findings[0].rule == "unsafe-deserialization/js-yaml-unsafe-schema"


def test_unsafe_deserialization_silent_safe_extend_of_default_schema(tmp_path: Path) -> None:
    # #395 C3: extending the SAFE DEFAULT_SCHEMA with a custom type is js-yaml's own documented,
    # safe pattern — it must NOT fire (the old bare `.extend(` matched every receiver).
    (tmp_path / "load.js").write_text(
        "const yaml = require('js-yaml');\n"
        "const data = yaml.load(input, { schema: yaml.DEFAULT_SCHEMA.extend([functionType]) });\n",
        encoding="utf-8",
    )
    assert UnsafeDeserializationGuard().run(tmp_path, mkprofile(tmp_path, features={"javascript"})) == []


def test_unsafe_deserialization_silent_commented_out_unsafe_schema(tmp_path: Path) -> None:
    # #395 M: a commented-out / documented example must not fire.
    (tmp_path / "load.js").write_text(
        "const yaml = require('js-yaml');\n"
        "// const data = yaml.load(input, { schema: DEFAULT_FULL_SCHEMA });\n",
        encoding="utf-8",
    )
    assert UnsafeDeserializationGuard().run(tmp_path, mkprofile(tmp_path, features={"javascript"})) == []


def test_unsafe_deserialization_js_types_import_does_not_taint_unrelated_call(tmp_path: Path) -> None:
    # #395 M: a file-wide js-yaml-js-types import must not taint a load whose own schema is safe
    # and does not reference the imported binding.
    (tmp_path / "load.js").write_text(
        "const yaml = require('js-yaml');\n"
        "const { all } = require('js-yaml-js-types');\n"
        "const strict = yaml.load(input, { schema: yaml.JSON_SCHEMA });\n",
        encoding="utf-8",
    )
    assert UnsafeDeserializationGuard().run(tmp_path, mkprofile(tmp_path, features={"javascript"})) == []


def test_unsafe_deserialization_flags_js_yaml_multiline_call(tmp_path: Path) -> None:
    # The dominant real-world style: options object spread across lines.
    (tmp_path / "load.js").write_text(
        "const yaml = require('js-yaml');\n"
        "const data = yaml.load(input, {\n"
        "  schema: DEFAULT_FULL_SCHEMA,\n"
        "  json: true,\n"
        "});\n",
        encoding="utf-8",
    )
    findings = UnsafeDeserializationGuard().run(tmp_path, mkprofile(tmp_path, features={"javascript"}))
    assert len(findings) == 1
    assert findings[0].location.endswith(":2")  # reported at the yaml.load( opening line


def test_unsafe_deserialization_js_pragma_suppresses(tmp_path: Path) -> None:
    (tmp_path / "load.js").write_text(
        "// security: allow-unsafe-deserialize\n"
        "const yaml = require('js-yaml');\n"
        "const data = yaml.load(input, { schema: DEFAULT_FULL_SCHEMA });\n",
        encoding="utf-8",
    )
    assert UnsafeDeserializationGuard().run(tmp_path, mkprofile(tmp_path, features={"javascript"})) == []


def test_unsafe_deserialization_js_silent_on_unrelated_load_call(tmp_path: Path) -> None:
    # FP-bait: an unrelated `.load(` on some other object, even with a `schema:`-shaped
    # option, isn't `yaml.load`/`.safeLoad` and must not fire.
    (tmp_path / "load.js").write_text(
        "const data = myOrmModel.load(id, { schema: 'v2' });\n",
        encoding="utf-8",
    )
    assert UnsafeDeserializationGuard().run(tmp_path, mkprofile(tmp_path, features={"javascript"})) == []



# --- #673: catastrophic backtracking on comment-blanked JS -------------------------------

# `_scan_js` scans a comment-blanked copy (#395), so a contiguous comment block becomes one
# contiguous whitespace run. The `\s+(.+?)\s*` shape in the js-yaml-js-types binding patterns
# matched a space in all three quantifiers, so it partitioned that run quadratically before
# failing on the absent trailing literal: 30.8s through the CLI on a 33 KB file, 90+ minutes on
# the 281 KB file that caught it. pytest-timeout cannot preempt this (see pyproject.toml), so
# these assert the wall clock themselves, the way test_walk.py does for #419.
_C673_COMMENT = "// ordinary explanatory comment line, nothing unsafe in here at all\n"
_C673_BLOCK = _C673_COMMENT * ((32 * 1024) // len(_C673_COMMENT))
# Wide window (0.07s healthy against a 30.8s regression, ~400x apart), so an absolute budget is
# comfortable here and no growth-ratio treatment is needed — see tests/_timing.py on when it is not.
_C673_BUDGET = register(
    TimingBudget(
        name="unsafe-deserialization/js-binding-backtracking",
        seconds=5.0,
        measured=0.074,
        regression=30.8,
        why="quadratic JS binding backtracking reintroduced (#673)",
    )
)


def _c673_run(tmp_path: Path, source: str) -> tuple[list[Finding], float]:
    """Run the guard over a single .tsx file, returning its findings and the elapsed seconds."""
    import time

    (tmp_path / "ink.tsx").write_text(source, encoding="utf-8")
    start = time.monotonic()
    findings = UnsafeDeserializationGuard().run(tmp_path, mkprofile(tmp_path, features={"typescript"}))
    return findings, time.monotonic() - start


def test_unsafe_deserialization_js_comment_block_after_const_stays_fast(tmp_path: Path) -> None:
    # The real trigger in hermes-agent's ink.tsx: a trailing `as const` immediately followed by a
    # 174 KB `//# sourceMappingURL=...base64` comment, which blanking turns into one whitespace run.
    findings, elapsed = _c673_run(tmp_path, "const MODES = ['warn'] as const\n" + _C673_BLOCK)
    assert findings == []
    assert_within(elapsed, _C673_BUDGET, "quadratic CJS binding backtracking reintroduced (#673)")


def test_unsafe_deserialization_js_comment_block_after_import_stays_fast(tmp_path: Path) -> None:
    # The ESM sibling has the same shape and blows up identically once an `import` token sits
    # next to the run. It survived the original report only because ink.tsx had no such token.
    findings, elapsed = _c673_run(tmp_path, "import\n" + _C673_BLOCK)
    assert findings == []
    assert_within(elapsed, _C673_BUDGET, "quadratic ESM binding backtracking reintroduced (#673)")


def test_unsafe_deserialization_js_comment_block_after_keyword_substring_stays_fast(
    tmp_path: Path,
) -> None:
    # The alternations carry no `\b`, so `Outlet` (React Router) anchored an attempt via its
    # `let`, and `reimport` via its `import`. Both measured the same curve as the real keywords.
    findings, elapsed = _c673_run(tmp_path, "export default Outlet\nawait reimport\n" + _C673_BLOCK)
    assert findings == []
    assert_within(elapsed, _C673_BUDGET, "unanchored keyword-substring backtracking reintroduced (#673)")


def test_unsafe_deserialization_js_comment_block_with_the_package_present_stays_fast(
    tmp_path: Path,
) -> None:
    # The guard's own target population. A file that really does import js-yaml-js-types skips
    # the substring pre-check, so this is the case the pre-check alone cannot save, and it still
    # has to detect. Bounding the patterns is what closes it.
    findings, elapsed = _c673_run(
        tmp_path,
        "const yaml = require('js-yaml');\n"
        "const { all } = require('js-yaml-js-types');\n"
        "const MODES = ['warn'] as const\n"
        + _C673_BLOCK
        + "const data = yaml.load(input, { schema: all });\n",
    )
    assert len(findings) == 1
    assert findings[0].rule == "unsafe-deserialization/js-yaml-unsafe-schema"
    assert_within(elapsed, _C673_BUDGET, "backtracking survives on the guard's own target files (#673)")


# --- #673: the ESM binding arm had no test at all before this ----------------------------


def test_unsafe_deserialization_flags_js_types_esm_named_import(tmp_path: Path) -> None:
    (tmp_path / "load.js").write_text(
        "import yaml from 'js-yaml';\n"
        "import { all } from 'js-yaml-js-types';\n"
        "const data = yaml.load(input, { schema: all });\n",
        encoding="utf-8",
    )
    findings = UnsafeDeserializationGuard().run(tmp_path, mkprofile(tmp_path, features={"javascript"}))
    assert len(findings) == 1
    assert findings[0].rule == "unsafe-deserialization/js-yaml-unsafe-schema"


def test_unsafe_deserialization_flags_js_types_esm_namespace_import(tmp_path: Path) -> None:
    (tmp_path / "load.js").write_text(
        'import yaml from "js-yaml";\n'
        'import * as jsTypes from "js-yaml-js-types";\n'
        "const data = yaml.load(input, { schema: jsTypes });\n",
        encoding="utf-8",
    )
    findings = UnsafeDeserializationGuard().run(tmp_path, mkprofile(tmp_path, features={"javascript"}))
    assert len(findings) == 1


def test_unsafe_deserialization_flags_js_types_esm_mixed_import(tmp_path: Path) -> None:
    (tmp_path / "load.js").write_text(
        "import yaml from 'js-yaml';\n"
        "import jsTypes, { all } from 'js-yaml-js-types';\n"
        "const data = yaml.load(input, { schema: all });\n",
        encoding="utf-8",
    )
    findings = UnsafeDeserializationGuard().run(tmp_path, mkprofile(tmp_path, features={"javascript"}))
    assert len(findings) == 1


def test_unsafe_deserialization_flags_js_types_cjs_across_a_newline(tmp_path: Path) -> None:
    # `\s+` spans the newline, so the binding clause starting on the next line still resolves.
    # Bounding the capture must not break this (it is why the bound is `[^\s]` + `[^\n;]`, not
    # a bare `[^\s]+`).
    (tmp_path / "load.js").write_text(
        "const yaml = require('js-yaml');\n"
        "const\n  { all } = require('js-yaml-js-types');\n"
        "const data = yaml.load(input, { schema: all });\n",
        encoding="utf-8",
    )
    findings = UnsafeDeserializationGuard().run(tmp_path, mkprofile(tmp_path, features={"javascript"}))
    assert len(findings) == 1


def test_unsafe_deserialization_js_types_keyword_substring_binds_nothing(tmp_path: Path) -> None:
    # FP bait for the `\b` narrowing: `constants`/`myvar`/`Outlet` are not binding keywords, so
    # nothing here may be treated as a js-yaml-js-types binding and taint the safe load below.
    (tmp_path / "load.js").write_text(
        "const yaml = require('js-yaml');\n"
        "const constants = require('js-yaml-js-types');\n"
        "export default Outlet;\n"
        "const strict = yaml.load(input, { schema: yaml.JSON_SCHEMA });\n",
        encoding="utf-8",
    )
    assert UnsafeDeserializationGuard().run(tmp_path, mkprofile(tmp_path, features={"javascript"})) == []


# --- #674 review: the bound is load-bearing, and its cost is pinned, not just described ---


def test_unsafe_deserialization_js_minified_line_with_semicolons_stays_fast(tmp_path: Path) -> None:
    # A second trigger shape #673 did not name: one minified line carrying many `const` anchors and
    # many `=`. Excluding `;` from the capture class is what keeps it inside a single statement. With
    # a bare `.` this is quadratic again (1.6s at 98KB, hanging by 400KB), so the class must not be
    # widened back to `.` to recover the `;`-in-a-default-value shape below.
    findings, elapsed = _c673_run(tmp_path, "const x = require('m'), w = f(); " * 8000)
    assert findings == []
    assert_within(elapsed, _C673_BUDGET, "minified-line backtracking reintroduced (#674 review)")


def test_unsafe_deserialization_js_minified_line_without_semicolons_stays_fast(
    tmp_path: Path,
) -> None:
    # The same line with nothing to terminate on, which is what the `{0,200}` cap covers: unbounded
    # it measures 0.04s / 0.57s / 8.8s at 7KB / 28KB / 112KB, capped it stays linear. Removing the
    # cap to widen the capture (see the false-negative test below) reopens exactly this.
    findings, elapsed = _c673_run(tmp_path, "const x = f() " * 8000)
    assert findings == []
    assert_within(elapsed, _C673_BUDGET, "unbounded-capture backtracking reintroduced (#674 review)")


def _binding_of_length(n: int) -> str:
    """A CJS binding whose CAPTURED clause is exactly `n` characters."""
    return "a" * n


def test_unsafe_deserialization_flags_js_types_binding_at_the_bound(tmp_path: Path) -> None:
    # Still-fires at the documented limit. `[^\s]` plus `[^\n;]{0,200}` captures at most 201
    # characters, so 201 is the last clause that may be mined, and it must be.
    name = _binding_of_length(201)
    (tmp_path / "load.js").write_text(
        "const yaml = require('js-yaml');\n"
        f"const {name} = require('js-yaml-js-types');\n"
        f"const data = yaml.load(input, {{ schema: {name} }});\n",
        encoding="utf-8",
    )
    findings = UnsafeDeserializationGuard().run(tmp_path, mkprofile(tmp_path, features={"javascript"}))
    assert len(findings) == 1
    assert findings[0].rule == "unsafe-deserialization/js-yaml-unsafe-schema"


def test_unsafe_deserialization_js_types_binding_past_the_bound_is_a_known_limit(
    tmp_path: Path,
) -> None:
    # The disclosed cost of the cap, pinned so it cannot drift silently: one character past the
    # limit the binding stops being mined, so a load referencing it is no longer tainted by it.
    # This is a FALSE NEGATIVE, accepted deliberately. Widening the capture to recover it reopens
    # the hang the two minified-line tests above cover, which is the trade the cap is making.
    # `js-yaml-js-types` exports `all` and `function`, so a 202-character clause is not a real shape.
    name = _binding_of_length(202)
    (tmp_path / "load.js").write_text(
        "const yaml = require('js-yaml');\n"
        f"const {name} = require('js-yaml-js-types');\n"
        f"const data = yaml.load(input, {{ schema: {name} }});\n",
        encoding="utf-8",
    )
    assert UnsafeDeserializationGuard().run(tmp_path, mkprofile(tmp_path, features={"javascript"})) == []


def test_unsafe_deserialization_flags_js_types_let_and_var_bindings(tmp_path: Path) -> None:
    # `let`/`var` were never positively tested, before or after #673, though the guard has always
    # claimed all three. They are also the two alternation arms `\b` narrowed, so this is the
    # still-fires direction for that narrowing.
    (tmp_path / "let.js").write_text(
        "const yaml = require('js-yaml');\n"
        "let { all } = require('js-yaml-js-types');\n"
        "const data = yaml.load(input, { schema: all });\n",
        encoding="utf-8",
    )
    (tmp_path / "var.js").write_text(
        "const yaml = require('js-yaml');\n"
        "var allTypes = require('js-yaml-js-types');\n"
        "const data = yaml.load(input, { schema: allTypes });\n",
        encoding="utf-8",
    )
    findings = UnsafeDeserializationGuard().run(tmp_path, mkprofile(tmp_path, features={"javascript"}))
    assert len(findings) == 2
    assert {f.rule for f in findings} == {"unsafe-deserialization/js-yaml-unsafe-schema"}


def test_unsafe_deserialization_js_pragma_quoted_in_a_string_does_not_suppress(tmp_path: Path) -> None:
    # #424 E4: the whole-file JS opt-out reads the comment-only view, so a string literal quoting
    # the pragma is content - only a real `//` comment (`..._js_pragma_suppresses`) opts out.
    (tmp_path / "load.js").write_text(
        'const help = "opt out with // security: allow-unsafe-deserialize";\n'
        "const yaml = require('js-yaml');\n"
        "const data = yaml.load(input, { schema: DEFAULT_FULL_SCHEMA });\n",
        encoding="utf-8",
    )
    findings = UnsafeDeserializationGuard().run(tmp_path, mkprofile(tmp_path, features={"javascript"}))
    assert len(findings) == 1


def test_unsafe_deserialization_pragma_quoted_in_a_string_on_the_line_does_not_suppress(tmp_path: Path) -> None:
    # #424 E4: the per-line Python check reads the same-length comment-only view, so a string on
    # the finding's own line quoting the pragma is content - only a real `#` comment opts out.
    (tmp_path / "c.py").write_text(
        "import pickle\n"
        "def load(b):\n"
        '    log("opt out with # security: allow-unsafe-deserialize"); return pickle.loads(b)\n',
        encoding="utf-8",
    )
    findings = UnsafeDeserializationGuard().run(tmp_path, _pyprof(tmp_path))
    assert [f.rule for f in findings] == ["unsafe-deserialization/untrusted-load"]


def test_unsafe_deserialization_trust_remote_code_pragma_quoted_in_a_kwarg_string_does_not_suppress(
    tmp_path: Path,
) -> None:
    # #424 E4: the `from_pretrained` span is sliced from the comment-only view, so a kwarg string
    # inside the call quoting the pragma is content - only a real trailing `#` comment opts out.
    (tmp_path / "m.py").write_text(
        "from transformers import AutoModelForCausalLM\n"
        "model = AutoModelForCausalLM.from_pretrained(\n"
        '    model_id, trust_remote_code=True, revision="opt out with # security: allow-unsafe-deserialize"\n'
        ")\n",
        encoding="utf-8",
    )
    findings = UnsafeDeserializationGuard().run(tmp_path, _pyprof(tmp_path))
    assert [f.rule for f in findings] == ["unsafe-deserialization/trust-remote-code-rce"]


# --- #1055 batch 1b: only live code counts, and the argument walk skips string content -------


def _js_yaml_run(tmp_path: Path, body: str) -> list[Finding]:
    (tmp_path / "load.js").write_text("const yaml = require('js-yaml');\n" + body, encoding="utf-8")
    return UnsafeDeserializationGuard().run(tmp_path, mkprofile(tmp_path, features={"javascript"}))


def test_unsafe_deserialization_js_paren_in_a_string_arg_does_not_end_the_call(tmp_path: Path) -> None:
    # #1055 sub-class 2: the walk counted the `)` inside `')'` as the call's close, so the
    # options object was never read and the CRITICAL went silent. Walked on the anchor mask it fires.
    findings = _js_yaml_run(
        tmp_path, "const data = yaml.load(input.replace(')', ''), { schema: DEFAULT_FULL_SCHEMA });\n"
    )
    assert [f.location for f in findings] == ["load.js:2"]


def test_unsafe_deserialization_js_brace_in_a_string_arg_does_not_end_the_call(tmp_path: Path) -> None:
    findings = _js_yaml_run(
        tmp_path, "const data = yaml.load(input.replace('}', ''), { schema: DEFAULT_FULL_SCHEMA });\n"
    )
    assert len(findings) == 1


def test_unsafe_deserialization_js_paren_in_a_template_arg_does_not_end_the_call(tmp_path: Path) -> None:
    findings = _js_yaml_run(
        tmp_path, "const data = yaml.load(`a: )${input}`, { schema: DEFAULT_FULL_SCHEMA });\n"
    )
    assert len(findings) == 1


def test_unsafe_deserialization_js_call_inside_a_substitution_still_fires(tmp_path: Path) -> None:
    # The shortcut-separating test: plain strip_strings=True would blank this live call.
    findings = _js_yaml_run(
        tmp_path, "const out = `${JSON.stringify(yaml.load(input, { schema: DEFAULT_FULL_SCHEMA }))}`;\n"
    )
    assert [f.location for f in findings] == ["load.js:2"]


def test_unsafe_deserialization_js_call_spelled_in_a_string_is_silent(tmp_path: Path) -> None:
    body = (
        "console.warn('never yaml.load(input, { schema: DEFAULT_FULL_SCHEMA }) on uploads');\n"
        "const help = `example: yaml.load(input, { schema: DEFAULT_FULL_SCHEMA })`;\n"
    )
    assert _js_yaml_run(tmp_path, body) == []


def test_unsafe_deserialization_js_real_call_after_a_quoted_copy_still_fires(tmp_path: Path) -> None:
    findings = _js_yaml_run(
        tmp_path, "log('yaml.load(x)'); const d = yaml.load(input, { schema: DEFAULT_FULL_SCHEMA });\n"
    )
    assert len(findings) == 1


def test_unsafe_deserialization_js_schema_name_in_a_string_value_is_silent(tmp_path: Path) -> None:
    # A real load with a real schema option whose dangerous name appears only inside a string.
    body = "const d = yaml.load(input, { schema: loadSchema('DEFAULT_FULL_SCHEMA.yml') });\n"
    assert _js_yaml_run(tmp_path, body) == []


def test_unsafe_deserialization_js_schema_key_in_a_string_value_is_silent(tmp_path: Path) -> None:
    # No real `schema:` option at all: the key and the name live only in a string value.
    body = "const d = yaml.load(input, { filename: 'schema: DEFAULT_FULL_SCHEMA' });\n"
    assert _js_yaml_run(tmp_path, body) == []


def test_unsafe_deserialization_js_types_binding_in_a_string_value_is_silent(tmp_path: Path) -> None:
    body = (
        "const { all } = require('js-yaml-js-types');\n"
        "const d = yaml.load(input, { schema: yaml.JSON_SCHEMA, filename: 'all.yml' });\n"
    )
    assert _js_yaml_run(tmp_path, body) == []


def test_unsafe_deserialization_js_types_binding_in_code_still_fires(tmp_path: Path) -> None:
    # The still-fires control for the test above: the same binding as live code.
    body = (
        "const { all } = require('js-yaml-js-types');\n"
        "const d = yaml.load(input, { schema: all, filename: 'all.yml' });\n"
    )
    assert len(_js_yaml_run(tmp_path, body)) == 1


def test_unsafe_deserialization_js_real_schema_after_quoted_copies_in_the_args_still_fires(tmp_path: Path) -> None:
    # Every signal match is tried (#1055 sub-class 3): quoted copies of `schema:` and of the
    # dangerous name earlier in the same args must not hide the real option after them.
    body = (
        "const d = yaml.load(input, { filename: 'schema: x', note: 'DEFAULT_FULL_SCHEMA', "
        "schema: DEFAULT_FULL_SCHEMA });\n"
    )
    assert len(_js_yaml_run(tmp_path, body)) == 1


def test_unsafe_deserialization_js_real_binding_after_a_quoted_copy_still_fires(tmp_path: Path) -> None:
    # The third signal kind (PR #1128 round 2, L5): a quoted copy of the js-types binding's name
    # ahead of the real `schema: all` must not hide it. The two tests above pin `schema:` and
    # `DEFAULT_FULL_SCHEMA`; this one fails if only the binding path reverts to a first-hit check.
    body = (
        "const { all } = require('js-yaml-js-types');\n"
        "const d = yaml.load(input, { note: 'all', schema: all });\n"
    )
    assert len(_js_yaml_run(tmp_path, body)) == 1


def test_unsafe_deserialization_js_walk_stops_at_the_real_close_fp_bait(tmp_path: Path) -> None:
    # FP-bait for the widened walk: past the quoted `)` it must still end at the call's own close,
    # so a neighbouring call's dangerous schema is not read as this call's option.
    body = (
        "const d = yaml.load(input.replace(')', ''), { schema: yaml.JSON_SCHEMA });\n"
        "other({ schema: DEFAULT_FULL_SCHEMA });\n"
    )
    assert _js_yaml_run(tmp_path, body) == []


def test_unsafe_deserialization_js_regex_literal_paren_is_a_known_limit(tmp_path: Path) -> None:
    # Pinned residual (#1055): the anchor mask keeps regex-literal bodies as code, so the `)` in
    # `/\)/g` still ends the argument walk early. Silent before and after; flip this when fixed.
    body = "const d = yaml.load(input.replace(/\\)/g, ''), { schema: DEFAULT_FULL_SCHEMA });\n"
    assert _js_yaml_run(tmp_path, body) == []
