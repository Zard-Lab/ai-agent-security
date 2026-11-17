from __future__ import annotations

from agentsec.guards.ruby_mass_assignment import RubyMassAssignmentGuard
from tests.guards._common import *  # noqa: F401,F403

_BANG = "ruby-mass-assignment/params-permit-bang"
_UNPROTECTED = "ruby-mass-assignment/unprotected-model-assignment"


# --- shape 1: params.permit! ------------------------------------------------------------


def test_ruby_mass_assignment_flags_the_canary_plant_shape(tmp_path: Path) -> None:
    # The exact text of the guard's own CanaryPlant file — the planted violation must fire.
    (tmp_path / "users_controller.rb").write_text(
        "class UsersController < ApplicationController\n"
        "  def create\n"
        "    User.create(params.permit!)\n"
        "  end\n"
        "end\n",
        encoding="utf-8",
    )
    findings = RubyMassAssignmentGuard().run(tmp_path, _rbprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == _BANG
    assert findings[0].severity == "high"


def test_ruby_mass_assignment_flags_permit_bang_after_require(tmp_path: Path) -> None:
    (tmp_path / "t.rb").write_text("attrs = params.require(:user).permit!\n", encoding="utf-8")
    findings = RubyMassAssignmentGuard().run(tmp_path, _rbprof(tmp_path))
    assert [f.rule for f in findings] == [_BANG]


def test_ruby_mass_assignment_flags_permit_bang_after_index(tmp_path: Path) -> None:
    (tmp_path / "t.rb").write_text("attrs = params[:user].permit!\n", encoding="utf-8")
    findings = RubyMassAssignmentGuard().run(tmp_path, _rbprof(tmp_path))
    assert [f.rule for f in findings] == [_BANG]


def test_ruby_mass_assignment_flags_permit_bang_on_a_named_params_helper(tmp_path: Path) -> None:
    (tmp_path / "t.rb").write_text("user_params.permit!\n", encoding="utf-8")
    findings = RubyMassAssignmentGuard().run(tmp_path, _rbprof(tmp_path))
    assert [f.rule for f in findings] == [_BANG]


def test_ruby_mass_assignment_silent_on_permit_allowlist(tmp_path: Path) -> None:
    # FP-bait: the non-bang form IS the fix — an explicit allowlist must never fire.
    (tmp_path / "t.rb").write_text(
        "params.require(:user).permit(:name, :email)\n", encoding="utf-8"
    )
    assert RubyMassAssignmentGuard().run(tmp_path, _rbprof(tmp_path)) == []


def test_ruby_mass_assignment_silent_on_a_domain_objects_own_permit_bang(tmp_path: Path) -> None:
    # FP-bait: `permit!` on something that is not a params object (an app that models
    # permissions can legitimately define its own bang method) must not fire.
    (tmp_path / "t.rb").write_text("@membership.permit!\n", encoding="utf-8")
    assert RubyMassAssignmentGuard().run(tmp_path, _rbprof(tmp_path)) == []


# --- shape 2: unprotected model write ---------------------------------------------------


def test_ruby_mass_assignment_flags_create_from_raw_params(tmp_path: Path) -> None:
    (tmp_path / "t.rb").write_text("User.create(params[:user])\n", encoding="utf-8")
    findings = RubyMassAssignmentGuard().run(tmp_path, _rbprof(tmp_path))
    assert [f.rule for f in findings] == [_UNPROTECTED]
    assert findings[0].severity == "high"


def test_ruby_mass_assignment_flags_update_on_an_instance_variable(tmp_path: Path) -> None:
    (tmp_path / "t.rb").write_text("@user.update(params[:user])\n", encoding="utf-8")
    findings = RubyMassAssignmentGuard().run(tmp_path, _rbprof(tmp_path))
    assert [f.rule for f in findings] == [_UNPROTECTED]


def test_ruby_mass_assignment_flags_namespaced_model_create_bang(tmp_path: Path) -> None:
    (tmp_path / "t.rb").write_text("Admin::User.create!(params[:user])\n", encoding="utf-8")
    findings = RubyMassAssignmentGuard().run(tmp_path, _rbprof(tmp_path))
    assert [f.rule for f in findings] == [_UNPROTECTED]


def test_ruby_mass_assignment_flags_assign_and_update_attributes(tmp_path: Path) -> None:
    (tmp_path / "t.rb").write_text(
        "@user.assign_attributes(params[:user])\n@other.update_attributes(params[:other])\n",
        encoding="utf-8",
    )
    findings = RubyMassAssignmentGuard().run(tmp_path, _rbprof(tmp_path))
    assert [f.rule for f in findings] == [_UNPROTECTED, _UNPROTECTED]


def test_ruby_mass_assignment_silent_when_permit_protects_inline(tmp_path: Path) -> None:
    # FP-bait: the same call shape WITH an allowlist on the same line must stay silent.
    (tmp_path / "t.rb").write_text(
        "User.create(params[:user].permit(:name, :email))\n", encoding="utf-8"
    )
    assert RubyMassAssignmentGuard().run(tmp_path, _rbprof(tmp_path)) == []


def test_ruby_mass_assignment_silent_when_require_permit_protects(tmp_path: Path) -> None:
    (tmp_path / "t.rb").write_text(
        "@user.update(params.require(:user).permit(:name))\n", encoding="utf-8"
    )
    assert RubyMassAssignmentGuard().run(tmp_path, _rbprof(tmp_path)) == []


def test_ruby_mass_assignment_silent_on_the_conventional_helper_idiom(tmp_path: Path) -> None:
    # FP-bait: the canonical Rails controller — a private `user_params` helper holding the
    # allowlist — is what correct code looks like, and must be completely silent.
    (tmp_path / "users_controller.rb").write_text(
        "class UsersController < ApplicationController\n"
        "  def create\n"
        "    @user = User.create(user_params)\n"
        "  end\n"
        "\n"
        "  def update\n"
        "    @user.update(user_params)\n"
        "  end\n"
        "\n"
        "  private\n"
        "\n"
        "  def user_params\n"
        "    params.require(:user).permit(:name, :email)\n"
        "  end\n"
        "end\n",
        encoding="utf-8",
    )
    assert RubyMassAssignmentGuard().run(tmp_path, _rbprof(tmp_path)) == []


def test_ruby_mass_assignment_silent_on_named_keyword_arguments(tmp_path: Path) -> None:
    # FP-bait: picking individual params by name is an allowlist by construction.
    (tmp_path / "t.rb").write_text(
        "@user.update(name: params[:name], email: params[:email])\n", encoding="utf-8"
    )
    assert RubyMassAssignmentGuard().run(tmp_path, _rbprof(tmp_path)) == []


def test_ruby_mass_assignment_silent_on_a_service_object_constructor(tmp_path: Path) -> None:
    # FP-bait for the deliberate `.new` scope-out: a service/form object built from params is
    # indistinguishable from a model constructor textually, so `.new` is not matched at all.
    (tmp_path / "t.rb").write_text("OrderCreator.new(params[:order]).call\n", encoding="utf-8")
    assert RubyMassAssignmentGuard().run(tmp_path, _rbprof(tmp_path)) == []


def test_ruby_mass_assignment_silent_on_a_read_only_query(tmp_path: Path) -> None:
    # FP-bait: params reaching a finder is not a write — `where`/`find_by` are not matched.
    (tmp_path / "t.rb").write_text(
        "User.where(params[:q])\nPost.find_by(params[:slug])\n", encoding="utf-8"
    )
    assert RubyMassAssignmentGuard().run(tmp_path, _rbprof(tmp_path)) == []


def test_ruby_mass_assignment_reports_permit_bang_once_not_twice(tmp_path: Path) -> None:
    # Both shapes are textually present on this line; it must produce ONE finding (the
    # higher-confidence bang rule), not a duplicate pair.
    (tmp_path / "t.rb").write_text("User.create(params.permit!)\n", encoding="utf-8")
    findings = RubyMassAssignmentGuard().run(tmp_path, _rbprof(tmp_path))
    assert [f.rule for f in findings] == [_BANG]


# --- suppression + comment handling -----------------------------------------------------


def test_ruby_mass_assignment_silent_in_comment(tmp_path: Path) -> None:
    (tmp_path / "t.rb").write_text(
        "# never call params.permit! here\n# and never User.create(params[:user])\nreal = 1\n",
        encoding="utf-8",
    )
    assert RubyMassAssignmentGuard().run(tmp_path, _rbprof(tmp_path)) == []


def test_ruby_mass_assignment_ignores_begin_end_block_comment(tmp_path: Path) -> None:
    (tmp_path / "t.rb").write_text(
        "=begin\nparams.permit! is the anti-pattern this guard flags\n=end\nreal = 1\n",
        encoding="utf-8",
    )
    assert RubyMassAssignmentGuard().run(tmp_path, _rbprof(tmp_path)) == []


def test_ruby_mass_assignment_pragma_silences_permit_bang(tmp_path: Path) -> None:
    (tmp_path / "t.rb").write_text(
        "params.permit!  # security: allow-ruby-mass-assignment\n", encoding="utf-8"
    )
    assert RubyMassAssignmentGuard().run(tmp_path, _rbprof(tmp_path)) == []


def test_ruby_mass_assignment_pragma_silences_model_write(tmp_path: Path) -> None:
    (tmp_path / "t.rb").write_text(
        "User.create(params[:user])  # security: allow-ruby-mass-assignment\n", encoding="utf-8"
    )
    assert RubyMassAssignmentGuard().run(tmp_path, _rbprof(tmp_path)) == []


def test_ruby_mass_assignment_not_applicable_without_ruby() -> None:
    prof = mkprofile(Path("/tmp"), features={"python"})
    assert RubyMassAssignmentGuard().applies(prof) is False
