from __future__ import annotations

from agentsec.guards.ruby_dangerous_dispatch import RubyDangerousDispatchGuard
from tests.guards._common import *  # noqa: F401,F403


def test_ruby_dangerous_dispatch_flags_params_lookup(tmp_path: Path) -> None:
    # The canary-plant shape: a controller dispatching on a request parameter.
    (tmp_path / "dispatch.rb").write_text(
        "class ReportsController\n"
        "  def run(record, params)\n"
        "    record.send(params[:action])\n"
        "  end\n"
        "end\n",
        encoding="utf-8",
    )
    findings = RubyDangerousDispatchGuard().run(tmp_path, _rbprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "ruby-dangerous-dispatch/non-literal-method-name"
    assert findings[0].severity == "high"
    assert findings[0].location.endswith(":3")


def test_ruby_dangerous_dispatch_silent_on_permit_allowlisted_loop_variable(tmp_path: Path) -> None:
    # FP-bait (#848 corpus scan, discourse/discourse app/controllers/admin/badges_controller.rb):
    # `key` is a block parameter of an `.each` over `allowed`, and `allowed` was itself already
    # passed through Rails' own strong-parameters `params.permit(*allowed)` -- the dispatched
    # setter name is drawn from a caller-approved allowlist, not attacker-chosen input.
    (tmp_path / "t.rb").write_text(
        "class BadgesController\n"
        "  def update\n"
        "    allowed -= [:query] unless SiteSetting.enable_badge_sql\n"
        "    params.permit(*allowed)\n"
        '    allowed.each { |key| badge.public_send("#{key}=", params[key]) if params[key] }\n'
        "  end\n"
        "end\n",
        encoding="utf-8",
    )
    assert RubyDangerousDispatchGuard().run(tmp_path, _rbprof(tmp_path)) == []


def test_ruby_dangerous_dispatch_flags_loop_variable_without_permit(tmp_path: Path) -> None:
    # The direction traded against (CLAUDE.md Rule 1): the identical `.each { |key| ... }`
    # dispatch shape, but with NO `.permit(` anywhere nearby, must still fire -- the exemption is
    # keyed on the demonstrated allowlist, not on the loop shape alone.
    (tmp_path / "t.rb").write_text(
        "class BadgesController\n"
        "  def update\n"
        '    fields.each { |key| badge.public_send("#{key}=", params[key]) if params[key] }\n'
        "  end\n"
        "end\n",
        encoding="utf-8",
    )
    findings = RubyDangerousDispatchGuard().run(tmp_path, _rbprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "ruby-dangerous-dispatch/non-literal-method-name"


def test_ruby_dangerous_dispatch_flags_receiver_reassigned_after_permit(tmp_path: Path) -> None:
    # Adversarial bypass caught in this guard's own self-test: `allowed` is rebuilt from an
    # attacker-controlled source AFTER `params.permit(*allowed)` ran and BEFORE the dispatch --
    # the exemption must not fire just because SOME earlier permit call once mentioned the name.
    (tmp_path / "t.rb").write_text(
        "class C\n"
        "  def update\n"
        "    params.permit(*allowed)\n"
        '    allowed = params[:attacker_supplied_list].split(",")\n'
        '    allowed.each { |key| badge.public_send("#{key}=", params[key]) if params[key] }\n'
        "  end\n"
        "end\n",
        encoding="utf-8",
    )
    findings = RubyDangerousDispatchGuard().run(tmp_path, _rbprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "ruby-dangerous-dispatch/non-literal-method-name"


def test_ruby_dangerous_dispatch_flags_permit_present_but_receiver_mismatch(tmp_path: Path) -> None:
    # The direction traded against: a `.permit(` call exists nearby, but for a DIFFERENT
    # variable than the one being iterated -- must still fire, not be exempted on the mere
    # presence of `.permit(` anywhere in the lookback window.
    (tmp_path / "t.rb").write_text(
        "class BadgesController\n"
        "  def update\n"
        "    params.permit(*other_list)\n"
        '    fields.each { |key| badge.public_send("#{key}=", params[key]) if params[key] }\n'
        "  end\n"
        "end\n",
        encoding="utf-8",
    )
    findings = RubyDangerousDispatchGuard().run(tmp_path, _rbprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "ruby-dangerous-dispatch/non-literal-method-name"


def test_ruby_dangerous_dispatch_flags_receiver_assigned_directly_from_params(tmp_path: Path) -> None:
    # PR #884 review regression (Dean's exact repro, a design-call finding): `.permit(*allowed)`
    # validates NOTHING about `allowed` itself -- Strong Parameters permits whatever names it is
    # handed. The old check treated "`.permit(` mentions `allowed` somewhere nearby" as sufficient
    # proof `allowed` was a developer-authored allowlist; it never checked where `allowed` itself
    # came from. `allowed = params[:fields]` (directly attacker-controlled) used to pass silently.
    (tmp_path / "t.rb").write_text(
        "class BadgesController\n"
        "  def update\n"
        "    allowed = params[:fields]\n"
        "    params.permit(*allowed)\n"
        '    allowed.each { |key| badge.public_send("#{key}=", params[key]) if params[key] }\n'
        "  end\n"
        "end\n",
        encoding="utf-8",
    )
    findings = RubyDangerousDispatchGuard().run(tmp_path, _rbprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "ruby-dangerous-dispatch/non-literal-method-name"


def test_ruby_dangerous_dispatch_flags_when_no_visible_assignment_to_receiver(tmp_path: Path) -> None:
    # Safe-direction default (Dean's suggested fix): no visible assignment to the receiver
    # anywhere in the lookback window is NOT assumed safe -- the guard can't tell whether the
    # receiver is a developer-authored constant defined further back, or something risky, so it
    # fails closed. Also closes the loose co-occurrence concern from the review: `.permit(:allowed)`
    # here is an unrelated field literally NAMED "allowed", not the splat-argument shape at all,
    # yet the identifier-mention check alone would still treat it as co-occurring.
    (tmp_path / "t.rb").write_text(
        "class C\n"
        "  def update\n"
        "    params.permit(:allowed)\n"
        '    allowed.each { |key| badge.public_send("#{key}=", params[key]) if params[key] }\n'
        "  end\n"
        "end\n",
        encoding="utf-8",
    )
    findings = RubyDangerousDispatchGuard().run(tmp_path, _rbprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "ruby-dangerous-dispatch/non-literal-method-name"


def test_ruby_dangerous_dispatch_flags_receiver_reassigned_via_compound_operator_after_permit(
    tmp_path: Path,
) -> None:
    # Separate finding, independent of Dean's 4: the pre-existing `_reassigned_between` regex
    # required a compound operator (`+=`/`-=`/...) to be followed by ANOTHER literal `=`, which
    # never occurs in real Ruby syntax -- so a compound reassignment between the permit call and
    # the dispatch silently defeated this guard's own adversarial-bypass protection entirely.
    # Verified directly: the old pattern never matched `allowed -= [...]` at all.
    (tmp_path / "t.rb").write_text(
        "class C\n"
        "  def update\n"
        "    allowed = [:name, :bio]\n"
        "    params.permit(*allowed)\n"
        '    allowed -= params[:attacker_supplied_list].split(",")\n'
        '    allowed.each { |key| badge.public_send("#{key}=", params[key]) if params[key] }\n'
        "  end\n"
        "end\n",
        encoding="utf-8",
    )
    findings = RubyDangerousDispatchGuard().run(tmp_path, _rbprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "ruby-dangerous-dispatch/non-literal-method-name"


def test_ruby_dangerous_dispatch_flags_bare_variable(tmp_path: Path) -> None:
    (tmp_path / "t.rb").write_text("obj.send(method_name)\n", encoding="utf-8")
    findings = RubyDangerousDispatchGuard().run(tmp_path, _rbprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "ruby-dangerous-dispatch/non-literal-method-name"


def test_ruby_dangerous_dispatch_flags_dunder_send(tmp_path: Path) -> None:
    (tmp_path / "t.rb").write_text("obj.__send__(meth)\n", encoding="utf-8")
    assert len(RubyDangerousDispatchGuard().run(tmp_path, _rbprof(tmp_path))) == 1


def test_ruby_dangerous_dispatch_flags_interpolated_symbol(tmp_path: Path) -> None:
    # A symbol BUILT by interpolation is not a plain literal -- it must still fire.
    (tmp_path / "t.rb").write_text('obj.public_send(:"#{action}")\n', encoding="utf-8")
    assert len(RubyDangerousDispatchGuard().run(tmp_path, _rbprof(tmp_path))) == 1


def test_ruby_dangerous_dispatch_flags_non_literal_try(tmp_path: Path) -> None:
    # Rails' `try` is in scope for the same reason Brakeman includes it: the method name is
    # still runtime-chosen. Only the NON-literal form fires (see the FP-bait test below).
    (tmp_path / "t.rb").write_text("user.try(attr)\n", encoding="utf-8")
    assert len(RubyDangerousDispatchGuard().run(tmp_path, _rbprof(tmp_path))) == 1


def test_ruby_dangerous_dispatch_flags_dispatch_inside_interpolation(tmp_path: Path) -> None:
    # Widening-direction guard for the string-span suppression: code inside `#{...}` is real
    # code, not string text, so the dispatch in it must still fire.
    (tmp_path / "t.rb").write_text('logger.debug("result: #{target.send(meth)}")\n', encoding="utf-8")
    assert len(RubyDangerousDispatchGuard().run(tmp_path, _rbprof(tmp_path))) == 1


def test_ruby_dangerous_dispatch_silent_on_literal_symbol(tmp_path: Path) -> None:
    # FP-bait: the safe, extremely common form -- a static symbol picks a fixed method.
    (tmp_path / "t.rb").write_text("obj.send(:save)\nobj.send(:save!, attrs)\n", encoding="utf-8")
    assert RubyDangerousDispatchGuard().run(tmp_path, _rbprof(tmp_path)) == []


def test_ruby_dangerous_dispatch_silent_on_literal_string(tmp_path: Path) -> None:
    (tmp_path / "t.rb").write_text('obj.send("save")\n', encoding="utf-8")
    assert RubyDangerousDispatchGuard().run(tmp_path, _rbprof(tmp_path)) == []


def test_ruby_dangerous_dispatch_silent_on_literal_try(tmp_path: Path) -> None:
    # FP-bait: `user.try(:name)` is the everyday Rails nil-safe idiom and must stay silent.
    (tmp_path / "t.rb").write_text("user.try(:name)\nuser.try(:profile)&.try(:avatar)\n", encoding="utf-8")
    assert RubyDangerousDispatchGuard().run(tmp_path, _rbprof(tmp_path)) == []


def test_ruby_dangerous_dispatch_silent_on_unrelated_method_names(tmp_path: Path) -> None:
    # FP-bait: ordinary Rails code whose method names merely contain/resemble the sinks.
    (tmp_path / "t.rb").write_text(
        "mailer.resend(message)\n"
        "send_report(user)\n"
        "user.update(name: params[:name])\n"
        "Notifier.deliver_later(payload)\n",
        encoding="utf-8",
    )
    assert RubyDangerousDispatchGuard().run(tmp_path, _rbprof(tmp_path)) == []


def test_ruby_dangerous_dispatch_silent_in_comment(tmp_path: Path) -> None:
    (tmp_path / "t.rb").write_text(
        "# never write record.send(params[:action]) here\nreal = 1\n", encoding="utf-8"
    )
    assert RubyDangerousDispatchGuard().run(tmp_path, _rbprof(tmp_path)) == []


def test_ruby_dangerous_dispatch_silent_in_block_comment(tmp_path: Path) -> None:
    (tmp_path / "t.rb").write_text(
        "=begin\nobj.send(meth) is the anti-pattern this documents\n=end\nreal = 1\n",
        encoding="utf-8",
    )
    assert RubyDangerousDispatchGuard().run(tmp_path, _rbprof(tmp_path)) == []


def test_ruby_dangerous_dispatch_silent_inside_string_literal(tmp_path: Path) -> None:
    # FP-bait: an error/guidance message that quotes the pattern is text, not a call site.
    (tmp_path / "t.rb").write_text(
        'raise ArgumentError, "use obj.send(:name), never obj.send(attr)"\n', encoding="utf-8"
    )
    assert RubyDangerousDispatchGuard().run(tmp_path, _rbprof(tmp_path)) == []


def test_ruby_dangerous_dispatch_pragma_silences(tmp_path: Path) -> None:
    (tmp_path / "t.rb").write_text(
        "obj.send(method_name)  # security: allow-dynamic-dispatch\n", encoding="utf-8"
    )
    assert RubyDangerousDispatchGuard().run(tmp_path, _rbprof(tmp_path)) == []


def test_ruby_dangerous_dispatch_skips_spec_tree_but_not_app_tree(tmp_path: Path) -> None:
    # Narrowing-direction pair: a spec's `described_class.send(meth)` metaprogramming is out of
    # scope, but the identical shape in app code must still fire.
    (tmp_path / "spec" / "models").mkdir(parents=True)
    (tmp_path / "spec" / "models" / "user_spec.rb").write_text(
        "described_class.send(meth)\n", encoding="utf-8"
    )
    (tmp_path / "app").mkdir()
    (tmp_path / "app" / "user.rb").write_text("record.send(meth)\n", encoding="utf-8")
    findings = RubyDangerousDispatchGuard().run(tmp_path, _rbprof(tmp_path))
    assert len(findings) == 1
    assert "app" in findings[0].location


def test_ruby_dangerous_dispatch_not_applicable_without_ruby() -> None:
    prof = mkprofile(Path("/tmp"), features={"python"})
    assert RubyDangerousDispatchGuard().applies(prof) is False
