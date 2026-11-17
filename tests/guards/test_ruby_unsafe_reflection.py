from __future__ import annotations

from agentsec.guards.ruby_unsafe_reflection import RubyUnsafeReflectionGuard
from tests.guards._common import *  # noqa: F401,F403


def test_ruby_unsafe_reflection_flags_params_constantize(tmp_path: Path) -> None:
    # The canary-plant shape: a request parameter picks which class gets instantiated.
    (tmp_path / "widgets_controller.rb").write_text(
        "class WidgetsController < ApplicationController\n"
        "  def create\n"
        "    klass = params[:type].constantize\n"
        "    render json: klass.new\n"
        "  end\n"
        "end\n",
        encoding="utf-8",
    )
    findings = RubyUnsafeReflectionGuard().run(tmp_path, _rbprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "ruby-unsafe-reflection/non-literal-class-name"
    assert findings[0].severity == "high"
    assert findings[0].location.endswith(":3")


def test_ruby_unsafe_reflection_flags_bare_variable(tmp_path: Path) -> None:
    (tmp_path / "t.rb").write_text("klass = klass_name.constantize\n", encoding="utf-8")
    findings = RubyUnsafeReflectionGuard().run(tmp_path, _rbprof(tmp_path))
    assert len(findings) == 1


def test_ruby_unsafe_reflection_flags_safe_constantize(tmp_path: Path) -> None:
    # safe_constantize returns nil instead of raising — a different failure mode, same danger.
    (tmp_path / "t.rb").write_text("k = record.type.safe_constantize\n", encoding="utf-8")
    assert len(RubyUnsafeReflectionGuard().run(tmp_path, _rbprof(tmp_path))) == 1


def test_ruby_unsafe_reflection_flags_interpolated_string(tmp_path: Path) -> None:
    (tmp_path / "t.rb").write_text(
        'handler = "#{params[:ns]}::Handler".constantize\n', encoding="utf-8"
    )
    assert len(RubyUnsafeReflectionGuard().run(tmp_path, _rbprof(tmp_path))) == 1


def test_ruby_unsafe_reflection_flags_const_get_with_variable(tmp_path: Path) -> None:
    (tmp_path / "t.rb").write_text("Object.const_get(params[:klass])\n", encoding="utf-8")
    assert len(RubyUnsafeReflectionGuard().run(tmp_path, _rbprof(tmp_path))) == 1


def test_ruby_unsafe_reflection_flags_qualified_const_get(tmp_path: Path) -> None:
    (tmp_path / "t.rb").write_text("mod.qualified_const_get(name)\n", encoding="utf-8")
    assert len(RubyUnsafeReflectionGuard().run(tmp_path, _rbprof(tmp_path))) == 1


def test_ruby_unsafe_reflection_flags_concatenated_const_get_argument(tmp_path: Path) -> None:
    # A literal PREFIX must not buy safety — the attacker still picks the suffix.
    (tmp_path / "t.rb").write_text('Object.const_get("App::" + kind)\n', encoding="utf-8")
    assert len(RubyUnsafeReflectionGuard().run(tmp_path, _rbprof(tmp_path))) == 1


def test_ruby_unsafe_reflection_silent_on_string_literal(tmp_path: Path) -> None:
    # FP-bait: the whole point is the NON-literal argument, so a literal must stay silent.
    (tmp_path / "t.rb").write_text('klass = "User".constantize\n', encoding="utf-8")
    assert RubyUnsafeReflectionGuard().run(tmp_path, _rbprof(tmp_path)) == []


def test_ruby_unsafe_reflection_silent_on_single_quoted_literal(tmp_path: Path) -> None:
    (tmp_path / "t.rb").write_text("k = 'Billing::Invoice'.safe_constantize\n", encoding="utf-8")
    assert RubyUnsafeReflectionGuard().run(tmp_path, _rbprof(tmp_path)) == []


def test_ruby_unsafe_reflection_silent_on_literal_const_get(tmp_path: Path) -> None:
    (tmp_path / "t.rb").write_text('Object.const_get("Widget")\n', encoding="utf-8")
    assert RubyUnsafeReflectionGuard().run(tmp_path, _rbprof(tmp_path)) == []


def test_ruby_unsafe_reflection_silent_on_symbol_const_get(tmp_path: Path) -> None:
    # FP-bait: a symbol literal is just as static as a string literal.
    (tmp_path / "t.rb").write_text("ActiveRecord::Base.const_get(:User)\n", encoding="utf-8")
    assert RubyUnsafeReflectionGuard().run(tmp_path, _rbprof(tmp_path)) == []


def test_ruby_unsafe_reflection_silent_on_allowlist_lookup(tmp_path: Path) -> None:
    # FP-bait: the remediation shape — an allowlist Hash, no reflection at all.
    (tmp_path / "t.rb").write_text(
        "EXPORTERS = { 'csv' => CsvExporter, 'pdf' => PdfExporter }.freeze\n"
        "def exporter_for(kind)\n"
        "  EXPORTERS.fetch(kind) { raise ArgumentError }\n"
        "end\n",
        encoding="utf-8",
    )
    assert RubyUnsafeReflectionGuard().run(tmp_path, _rbprof(tmp_path)) == []


def test_ruby_unsafe_reflection_silent_on_own_method_definition(tmp_path: Path) -> None:
    # FP-bait: a library DEFINING its own reflection helper is not calling one.
    (tmp_path / "t.rb").write_text(
        "class Resolver\n  def self.constantize(name)\n    name\n  end\nend\n", encoding="utf-8"
    )
    assert RubyUnsafeReflectionGuard().run(tmp_path, _rbprof(tmp_path)) == []


def test_ruby_unsafe_reflection_silent_on_deconstantize(tmp_path: Path) -> None:
    # FP-bait: `deconstantize` is a different (string-trimming) ActiveSupport method.
    (tmp_path / "t.rb").write_text('parent = klass_name.deconstantize\n', encoding="utf-8")
    assert RubyUnsafeReflectionGuard().run(tmp_path, _rbprof(tmp_path)) == []


def test_ruby_unsafe_reflection_silent_in_comment(tmp_path: Path) -> None:
    (tmp_path / "t.rb").write_text(
        "# Never write params[:type].constantize here\nreal = 1\n", encoding="utf-8"
    )
    assert RubyUnsafeReflectionGuard().run(tmp_path, _rbprof(tmp_path)) == []


def test_ruby_unsafe_reflection_silent_in_begin_end_block_comment(tmp_path: Path) -> None:
    (tmp_path / "t.rb").write_text(
        "=begin\nparams[:type].constantize is the anti-pattern\n=end\nreal = 1\n", encoding="utf-8"
    )
    assert RubyUnsafeReflectionGuard().run(tmp_path, _rbprof(tmp_path)) == []


def test_ruby_unsafe_reflection_pragma_silences(tmp_path: Path) -> None:
    (tmp_path / "t.rb").write_text(
        "klass = type_name.constantize  # security: allow-unsafe-reflection\n", encoding="utf-8"
    )
    assert RubyUnsafeReflectionGuard().run(tmp_path, _rbprof(tmp_path)) == []


def test_ruby_unsafe_reflection_skips_spec_tree_but_not_app_tree(tmp_path: Path) -> None:
    # Narrowing-direction pair: RSpec metaprogramming resolves class names from variables on
    # purpose, but the identical shape in app code must still fire. Mirrors
    # test_ruby_dangerous_dispatch_skips_spec_tree_but_not_app_tree, which scopes out the same
    # RSpec shape for the sibling dispatch guard.
    (tmp_path / "spec").mkdir()
    (tmp_path / "spec" / "factories.rb").write_text(
        "params_type.constantize\n", encoding="utf-8"
    )
    (tmp_path / "app").mkdir()
    (tmp_path / "app" / "widget.rb").write_text(
        "params[:type].constantize\n", encoding="utf-8"
    )
    findings = RubyUnsafeReflectionGuard().run(tmp_path, _rbprof(tmp_path))
    assert len(findings) == 1
    assert "app" in findings[0].location


def test_ruby_unsafe_reflection_not_applicable_without_ruby() -> None:
    prof = mkprofile(Path("/tmp"), features={"python"})
    assert RubyUnsafeReflectionGuard().applies(prof) is False
