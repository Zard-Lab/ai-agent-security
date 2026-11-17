from __future__ import annotations

from agentsec.guards.ruby_unsafe_deserialization import RubyUnsafeDeserializationGuard
from tests.guards._common import *  # noqa: F401,F403


def test_ruby_unsafe_deserialization_flags_marshal_load(tmp_path: Path) -> None:
    # The canary-plant shape.
    (tmp_path / "session_store.rb").write_text(
        "def restore_session(blob)\n  Marshal.load(blob)\nend\n", encoding="utf-8"
    )
    findings = RubyUnsafeDeserializationGuard().run(tmp_path, _rbprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "ruby-unsafe-deserialization/marshal-load"
    assert findings[0].severity == "critical"
    assert findings[0].location.endswith(":2")


def test_ruby_unsafe_deserialization_flags_marshal_restore(tmp_path: Path) -> None:
    (tmp_path / "t.rb").write_text("obj = Marshal.restore(blob)\n", encoding="utf-8")
    findings = RubyUnsafeDeserializationGuard().run(tmp_path, _rbprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "ruby-unsafe-deserialization/marshal-load"


def test_ruby_unsafe_deserialization_flags_marshal_colon_separator(tmp_path: Path) -> None:
    # `Marshal::load(x)` is legal Ruby and still appears in older code.
    (tmp_path / "t.rb").write_text("obj = Marshal::load(blob)\n", encoding="utf-8")
    assert len(RubyUnsafeDeserializationGuard().run(tmp_path, _rbprof(tmp_path))) == 1


def test_ruby_unsafe_deserialization_flags_yaml_load(tmp_path: Path) -> None:
    (tmp_path / "t.rb").write_text("cfg = YAML.load(request.body.read)\n", encoding="utf-8")
    findings = RubyUnsafeDeserializationGuard().run(tmp_path, _rbprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "ruby-unsafe-deserialization/yaml-unsafe-load"
    assert findings[0].severity == "critical"


def test_ruby_unsafe_deserialization_flags_psych_load(tmp_path: Path) -> None:
    (tmp_path / "t.rb").write_text("cfg = Psych.load(doc)\n", encoding="utf-8")
    findings = RubyUnsafeDeserializationGuard().run(tmp_path, _rbprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "ruby-unsafe-deserialization/yaml-unsafe-load"


def test_ruby_unsafe_deserialization_flags_oj_object_load(tmp_path: Path) -> None:
    (tmp_path / "t.rb").write_text("o = Oj.object_load(body)\n", encoding="utf-8")
    findings = RubyUnsafeDeserializationGuard().run(tmp_path, _rbprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "ruby-unsafe-deserialization/oj-object-mode-load"


def test_ruby_unsafe_deserialization_flags_oj_load_object_mode(tmp_path: Path) -> None:
    (tmp_path / "t.rb").write_text("o = Oj.load(body, mode: :object)\n", encoding="utf-8")
    findings = RubyUnsafeDeserializationGuard().run(tmp_path, _rbprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "ruby-unsafe-deserialization/oj-object-mode-load"


def test_ruby_unsafe_deserialization_flags_oj_load_hash_rocket_mode(tmp_path: Path) -> None:
    (tmp_path / "t.rb").write_text("o = Oj.load(body, :mode => :object)\n", encoding="utf-8")
    assert len(RubyUnsafeDeserializationGuard().run(tmp_path, _rbprof(tmp_path))) == 1


def test_ruby_unsafe_deserialization_silent_on_yaml_safe_load(tmp_path: Path) -> None:
    # The SAFE form is the fix — it must never fire.
    (tmp_path / "t.rb").write_text(
        "cfg = YAML.safe_load(doc, permitted_classes: [Date], aliases: true)\n", encoding="utf-8"
    )
    assert RubyUnsafeDeserializationGuard().run(tmp_path, _rbprof(tmp_path)) == []


def test_ruby_unsafe_deserialization_silent_on_marshal_dump(tmp_path: Path) -> None:
    # FP-bait: serialization is not a sink; only the load side executes the payload.
    (tmp_path / "t.rb").write_text("blob = Marshal.dump(obj)\n", encoding="utf-8")
    assert RubyUnsafeDeserializationGuard().run(tmp_path, _rbprof(tmp_path)) == []


def test_ruby_unsafe_deserialization_silent_on_deep_copy_idiom(tmp_path: Path) -> None:
    # FP-bait: `Marshal.load(Marshal.dump(obj))` is the canonical Ruby deep-copy one-liner —
    # the bytes never leave the expression, so there is no untrusted input.
    (tmp_path / "t.rb").write_text("copy = Marshal.load(Marshal.dump(record))\n", encoding="utf-8")
    assert RubyUnsafeDeserializationGuard().run(tmp_path, _rbprof(tmp_path)) == []


def test_ruby_unsafe_deserialization_deep_copy_exemption_does_not_kill_real_detection(
    tmp_path: Path,
) -> None:
    # The direction traded against the deep-copy narrowing: a dump whose bytes travel through a
    # variable (or a cache, or another process) is NOT that idiom and must still fire.
    (tmp_path / "t.rb").write_text(
        "blob = Marshal.dump(record)\ncopy = Marshal.load(blob)\n", encoding="utf-8"
    )
    findings = RubyUnsafeDeserializationGuard().run(tmp_path, _rbprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].location.endswith(":2")


def test_ruby_unsafe_deserialization_silent_on_bare_oj_load(tmp_path: Path) -> None:
    # FP-bait: the dominant real-world Oj call shape. Its mode comes from `Oj.default_options`,
    # which is not resolvable at the call site — a disclosed FN, deliberately not an FP source.
    (tmp_path / "t.rb").write_text("o = Oj.load(response.body)\n", encoding="utf-8")
    assert RubyUnsafeDeserializationGuard().run(tmp_path, _rbprof(tmp_path)) == []


def test_ruby_unsafe_deserialization_silent_on_oj_load_strict_mode(tmp_path: Path) -> None:
    (tmp_path / "t.rb").write_text("o = Oj.load(body, mode: :strict)\n", encoding="utf-8")
    assert RubyUnsafeDeserializationGuard().run(tmp_path, _rbprof(tmp_path)) == []


def test_ruby_unsafe_deserialization_silent_on_yaml_load_file(tmp_path: Path) -> None:
    # FP-bait: `YAML.load_file` on a repo-local config file is the dominant real use of the
    # load_file API; it is deliberately outside this guard's patterns.
    (tmp_path / "t.rb").write_text(
        "cfg = YAML.load_file(Rails.root.join('config/app.yml'))\n", encoding="utf-8"
    )
    assert RubyUnsafeDeserializationGuard().run(tmp_path, _rbprof(tmp_path)) == []


def test_ruby_unsafe_deserialization_silent_on_unrelated_load_calls(tmp_path: Path) -> None:
    # FP-bait: ordinary Rails/ActiveRecord code that merely contains the word `load`.
    (tmp_path / "t.rb").write_text(
        "I18n.load_path += Dir[Rails.root.join('config/locales/*.yml')]\n"
        "users = User.where(active: true).load\n"
        "data = JSON.parse(response.body)\n"
        "os.marshal_load(attributes)\n",
        encoding="utf-8",
    )
    assert RubyUnsafeDeserializationGuard().run(tmp_path, _rbprof(tmp_path)) == []


def test_ruby_unsafe_deserialization_silent_in_comment(tmp_path: Path) -> None:
    (tmp_path / "t.rb").write_text(
        "# Never call Marshal.load(blob) on user input\nreal = 1\n", encoding="utf-8"
    )
    assert RubyUnsafeDeserializationGuard().run(tmp_path, _rbprof(tmp_path)) == []


def test_ruby_unsafe_deserialization_silent_in_begin_end_block_comment(tmp_path: Path) -> None:
    (tmp_path / "t.rb").write_text(
        "=begin\nYAML.load(doc) is the unsafe loader, do not use\n=end\nreal = 1\n",
        encoding="utf-8",
    )
    assert RubyUnsafeDeserializationGuard().run(tmp_path, _rbprof(tmp_path)) == []


def test_ruby_unsafe_deserialization_pragma_silences(tmp_path: Path) -> None:
    (tmp_path / "t.rb").write_text(
        "Marshal.load(cache_blob)  # security: allow-ruby-unsafe-deserialize\n"
        "YAML.load(doc)  # security: allow-ruby-unsafe-deserialize\n",
        encoding="utf-8",
    )
    assert RubyUnsafeDeserializationGuard().run(tmp_path, _rbprof(tmp_path)) == []


def test_ruby_unsafe_deserialization_not_applicable_without_ruby() -> None:
    prof = mkprofile(Path("/tmp"), features={"python"})
    assert RubyUnsafeDeserializationGuard().applies(prof) is False
