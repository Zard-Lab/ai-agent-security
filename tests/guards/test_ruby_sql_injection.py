from __future__ import annotations

from agentsec.guards.ruby_sql_injection import RubySqlInjectionGuard
from tests.guards._common import *  # noqa: F401,F403


def _run(tmp_path: Path, src: str, name: str = "t.rb") -> list:
    (tmp_path / name).write_text(src, encoding="utf-8")
    return RubySqlInjectionGuard().run(tmp_path, _rbprof(tmp_path))


def test_ruby_sql_injection_flags_canary_plant_shape(tmp_path: Path) -> None:
    # The exact canary plant: interpolation spliced into the raw WHERE text.
    src = RubySqlInjectionGuard.canary_plant.files["user_search.rb"]
    findings = _run(tmp_path, src, "user_search.rb")
    assert len(findings) == 1
    assert findings[0].rule == "ruby-sql-injection/interpolated-sql"
    assert findings[0].severity == "high"


def test_ruby_sql_injection_flags_find_by_sql(tmp_path: Path) -> None:
    findings = _run(tmp_path, 'Order.find_by_sql("SELECT * FROM orders WHERE id = #{id}")\n')
    assert len(findings) == 1
    assert findings[0].rule == "ruby-sql-injection/interpolated-sql"


def test_ruby_sql_injection_flags_order_direction(tmp_path: Path) -> None:
    # ORDER BY direction injection — no SQL keyword on the line, so the sink name is the anchor.
    assert len(_run(tmp_path, 'Post.order("created_at #{params[:dir]}")\n')) == 1


def test_ruby_sql_injection_flags_bare_where_in_scope_lambda(tmp_path: Path) -> None:
    # Rails writes `where(...)` without an explicit receiver inside a model scope.
    assert len(_run(tmp_path, 'scope :recent, -> { where("created_at > #{t}") }\n')) == 1


def test_ruby_sql_injection_flags_calculate_second_argument(tmp_path: Path) -> None:
    # `calculate(operation, column_name)` carries its SQL fragment in the SECOND argument.
    assert len(_run(tmp_path, 'User.calculate(:sum, "price * #{rate}")\n')) == 1


def test_ruby_sql_injection_silent_on_coerced_join_interpolation(tmp_path: Path) -> None:
    # FP-bait (#848 corpus scan, discourse/discourse app/models/topic.rb): every element is
    # forced through `.to_i` before being joined, so however the underlying values got there,
    # what lands in the SQL text can only ever be digits/commas -- never SQL syntax.
    src = 'Topic.order("array_position(ARRAY[#{candidate_ids.map(&:to_i).join(",")}]::int[], id)")\n'
    assert _run(tmp_path, src) == []


def test_ruby_sql_injection_silent_on_bare_to_i_interpolation(tmp_path: Path) -> None:
    # FP-bait: a single value coerced inline with `.to_i` cannot carry SQL syntax either.
    src = 'Post.where("id = #{params[:id].to_i}")\n'
    assert _run(tmp_path, src) == []


def test_ruby_sql_injection_flags_tainted_value_beside_unrelated_coercion(tmp_path: Path) -> None:
    # PR #884 review regression (Dean's exact repro): the pre-fix regexes were UNANCHORED
    # .search() calls, so "a coercion appears SOMEWHERE in the interpolation" was wrongly accepted
    # as "the WHOLE interpolated value is coerced" -- contradicting this guard's own docstring. A
    # genuinely tainted `params[:id]` sitting beside an unrelated `0.to_i` literal used to read as
    # fully safe. A real, silent SQL-injection false negative; now anchored so the entire
    # expression must be the coercion chain, not merely contain one.
    src = 'Post.where("id = #{params[:id] || 0.to_i}")\n'
    findings = _run(tmp_path, src)
    assert len(findings) == 1
    assert findings[0].rule == "ruby-sql-injection/interpolated-sql"


def test_ruby_sql_injection_flags_tainted_prefix_before_coerced_join(tmp_path: Path) -> None:
    # PR #884 review regression, the .join() sibling of the case above: an attacker-controlled
    # prefix concatenated in front of an otherwise-coerced `.map(&:to_i).join(...)` used to read as
    # fully safe under the unanchored form, since the coercion appeared somewhere in the string.
    src = 'Topic.where("id IN (#{malicious_prefix + ids.map(&:to_i).join(",")})")\n'
    findings = _run(tmp_path, src)
    assert len(findings) == 1
    assert findings[0].rule == "ruby-sql-injection/interpolated-sql"


def test_ruby_sql_injection_flags_coercion_on_method_call_result_disclosed_residual(
    tmp_path: Path,
) -> None:
    # Disclosed trade-off from the PR #884 review fix (CLAUDE.md Rule 1 — the widening/anchoring
    # needs a test for what it now re-fires on, not just what it now correctly catches). Anchoring
    # the coercion regexes to the FULL expression means a coercion applied to a METHOD CALL's
    # result (parens in the chain, e.g. `some_method(x).to_i`) no longer matches the bare
    # identifier-chain grammar and is treated as NOT exempt — even though `.to_i` as the terminal
    # operation on the whole expression makes it provably just as safe as the exempted shapes.
    # Accepted deliberately: the safe direction for a security EXEMPTION is to under-exempt (an
    # occasional false positive) rather than over-exempt (a false negative), matching this guard's
    # own stated INLINE-shape-only scope decision for the coercion exemption. Not silently assumed
    # — this test pins the current (conservative) behavior so a future widening is a deliberate,
    # reviewed choice, not a silent regression discovered later.
    src = 'Post.where("id = #{lookup_id(params[:raw]).to_i}")\n'
    findings = _run(tmp_path, src)
    assert len(findings) == 1
    assert findings[0].rule == "ruby-sql-injection/interpolated-sql"


def test_ruby_sql_injection_flags_uncoerced_join_interpolation(tmp_path: Path) -> None:
    # The direction traded against (CLAUDE.md Rule 1): a `.join(...)` with NO coercion anywhere
    # in the interpolated expression must still fire -- the guard doesn't trace whether `ids` was
    # coerced on an EARLIER line (a disclosed residual, not silently assumed safe here).
    src = 'Topic.where("topics.category_id NOT IN (#{ids.join(",")})")\n'
    findings = _run(tmp_path, src)
    assert len(findings) == 1
    assert findings[0].rule == "ruby-sql-injection/interpolated-sql"


def test_ruby_sql_injection_flags_mixed_coerced_and_tainted_interpolation(tmp_path: Path) -> None:
    # The direction traded against: if ANY interpolation in the argument is not numeric-coerced,
    # the whole call still fires, even alongside one that is.
    src = 'Post.where("id = #{params[:id].to_i} AND name = \'#{params[:name]}\'")\n'
    findings = _run(tmp_path, src)
    assert len(findings) == 1
    assert findings[0].rule == "ruby-sql-injection/interpolated-sql"


def test_ruby_sql_injection_silent_on_positional_placeholder(tmp_path: Path) -> None:
    # FP-bait / the safe fix: placeholder in the SQL text, value in a separate bind argument.
    assert _run(tmp_path, 'User.where("name = ?", name)\n') == []


def test_ruby_sql_injection_silent_on_named_placeholder(tmp_path: Path) -> None:
    assert _run(tmp_path, 'User.where("id = :id", id: id)\n') == []


def test_ruby_sql_injection_silent_on_hash_form(tmp_path: Path) -> None:
    assert _run(tmp_path, "User.where(id: id)\n") == []


def test_ruby_sql_injection_silent_on_hash_value_built_by_interpolation(tmp_path: Path) -> None:
    # The documented scope decision: interpolation inside a hash VALUE is still parameterized by
    # ActiveRecord — only interpolation inside the raw SQL STRING is injectable.
    assert _run(tmp_path, 'User.where(name: "#{prefix}_suffix")\n') == []


def test_ruby_sql_injection_silent_on_interpolated_bind_argument(tmp_path: Path) -> None:
    # Interpolation on a SIBLING argument must not leak into the SQL-text argument's check.
    assert _run(tmp_path, 'User.where("name = ?", "#{prefix}_x")\n') == []


def test_ruby_sql_injection_silent_on_static_rails_scope(tmp_path: Path) -> None:
    # Realistic FP-bait: ordinary static query fragments a real Rails app writes every day.
    src = 'scope :live, -> { where("deleted_at IS NULL").order(:created_at) }\nUser.select("id, name")\n'
    assert _run(tmp_path, src) == []


def test_ruby_sql_injection_silent_on_find_by_sql_bind_array(tmp_path: Path) -> None:
    assert _run(tmp_path, 'Order.find_by_sql(["SELECT * FROM o WHERE id = ?", id])\n') == []


def test_ruby_sql_injection_silent_on_single_quoted_literal(tmp_path: Path) -> None:
    # Ruby single-quoted strings do not interpolate — `#{x}` there is literal text.
    assert _run(tmp_path, "User.where('name = #{x}')\n") == []


def test_ruby_sql_injection_silent_on_longer_identifier(tmp_path: Path) -> None:
    # `reselect` ends in `select` but is a different method — the lookbehind must reject it.
    assert _run(tmp_path, 'User.reselect("id = #{x}")\n') == []


def test_ruby_sql_injection_silent_outside_a_sink(tmp_path: Path) -> None:
    # Interpolation is pervasive in Ruby; only an ActiveRecord query sink makes it SQL.
    assert _run(tmp_path, 'log.info("user #{id} searched")\nredirect_to "#{root_path}?q=#{q}"\n') == []


def test_ruby_sql_injection_silent_in_comment(tmp_path: Path) -> None:
    assert _run(tmp_path, '# BAD: User.where("id = #{id}")\nreal = 1\n') == []


def test_ruby_sql_injection_silent_in_block_comment(tmp_path: Path) -> None:
    assert _run(tmp_path, '=begin\nUser.where("id = #{id}")\n=end\nreal = 1\n') == []


def test_ruby_sql_injection_silent_in_trailing_comment(tmp_path: Path) -> None:
    assert _run(tmp_path, 'x = 1  # see User.where("id = #{id}")\n') == []


def test_ruby_sql_injection_pragma_silences(tmp_path: Path) -> None:
    # The pragma is itself a `#` comment, so it must be matched on the RAW line.
    assert _run(tmp_path, 'User.where("id = #{id}")  # security: allow-ruby-sql-injection\n') == []


def test_ruby_sql_injection_skips_spec_tree_but_not_app_tree(tmp_path: Path) -> None:
    # Narrowing-direction pair: a spec splicing a literal flag into a fragment is out of scope,
    # but the identical shape in app code must still fire. Matches the skip the three siblings on
    # this checklist item already make (sqlalchemy-text-parameterized / js- / go-sql-injection).
    (tmp_path / "spec" / "models").mkdir(parents=True)
    (tmp_path / "spec" / "models" / "user_spec.rb").write_text(
        'User.where("active = #{true_flag}")\n', encoding="utf-8"
    )
    (tmp_path / "app").mkdir()
    (tmp_path / "app" / "user.rb").write_text(
        'User.where("active = #{flag}")\n', encoding="utf-8"
    )
    findings = RubySqlInjectionGuard().run(tmp_path, _rbprof(tmp_path))
    assert len(findings) == 1
    assert "app" in findings[0].location


def test_ruby_sql_injection_not_applicable_without_ruby() -> None:
    prof = mkprofile(Path("/tmp"), features={"python"})
    assert RubySqlInjectionGuard().applies(prof) is False
