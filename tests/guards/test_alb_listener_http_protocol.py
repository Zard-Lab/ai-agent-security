from __future__ import annotations

from agentsec.guards.alb_listener_http_protocol import AlbListenerHttpProtocolGuard
from tests.guards._common import *  # noqa: F401,F403

_RULE = "alb-listener-http-protocol/plaintext-listener"


def _run(tmp_path: Path, content: str) -> list:
    (tmp_path / "alb.tf").write_text(content, encoding="utf-8")
    return AlbListenerHttpProtocolGuard().run(tmp_path, _tf_prof(tmp_path))


def test_http_listener_fires(tmp_path: Path) -> None:
    findings = _run(tmp_path, (
        'resource "aws_lb_listener" "front_end" {\n'
        "  load_balancer_arn = aws_lb.main.arn\n"
        '  port              = "80"\n'
        '  protocol          = "HTTP"\n'
        "\n"
        "  default_action {\n"
        '    type             = "forward"\n'
        "    target_group_arn = aws_lb_target_group.main.arn\n"
        "  }\n"
        "}\n"
    ))
    matches = [f for f in findings if f.rule == _RULE]
    assert len(matches) == 1
    assert matches[0].severity == "medium"
    assert "alb.tf" in matches[0].location


def test_https_listener_silent(tmp_path: Path) -> None:
    findings = _run(tmp_path, (
        'resource "aws_lb_listener" "front_end" {\n'
        "  load_balancer_arn = aws_lb.main.arn\n"
        '  port              = "443"\n'
        '  protocol          = "HTTPS"\n'
        "  ssl_policy        = \"ELBSecurityPolicy-TLS13-1-2-2021-06\"\n"
        "  certificate_arn   = aws_acm_certificate.main.arn\n"
        "\n"
        "  default_action {\n"
        '    type             = "forward"\n'
        "    target_group_arn = aws_lb_target_group.main.arn\n"
        "  }\n"
        "}\n"
    ))
    assert not any(f.rule == _RULE for f in findings)


def test_tcp_listener_silent(tmp_path: Path) -> None:
    findings = _run(tmp_path, (
        'resource "aws_lb_listener" "nlb" {\n'
        "  load_balancer_arn = aws_lb.nlb.arn\n"
        '  port              = "80"\n'
        '  protocol          = "TCP"\n'
        "\n"
        "  default_action {\n"
        '    type             = "forward"\n'
        "    target_group_arn = aws_lb_target_group.nlb.arn\n"
        "  }\n"
        "}\n"
    ))
    assert not any(f.rule == _RULE for f in findings)


def test_http_listener_redirecting_to_https_stays_silent(tmp_path: Path) -> None:
    # The canonical, already-hardened port-80 listener: protocol = "HTTP" but every
    # default_action immediately redirects to HTTPS, serving no content in the clear
    # (review H4a FP-bait -- this used to fire).
    findings = _run(tmp_path, (
        'resource "aws_lb_listener" "front_end" {\n'
        "  load_balancer_arn = aws_lb.main.arn\n"
        '  port              = "80"\n'
        '  protocol          = "HTTP"\n'
        "\n"
        "  default_action {\n"
        '    type = "redirect"\n'
        "    redirect {\n"
        '      port        = "443"\n'
        '      protocol    = "HTTPS"\n'
        '      status_code = "HTTP_301"\n'
        "    }\n"
        "  }\n"
        "}\n"
    ))
    assert not any(f.rule == _RULE for f in findings)


def test_http_listener_forwarding_still_fires(tmp_path: Path) -> None:
    # Same top-level protocol = "HTTP", but the action actually serves content (forward)
    # rather than redirecting -- must still fire (review H4a: not every default_action is a
    # safe redirect, so this direction must stay tested too).
    findings = _run(tmp_path, (
        'resource "aws_lb_listener" "front_end" {\n'
        "  load_balancer_arn = aws_lb.main.arn\n"
        '  port              = "80"\n'
        '  protocol          = "HTTP"\n'
        "\n"
        "  default_action {\n"
        '    type             = "forward"\n'
        "    target_group_arn = aws_lb_target_group.main.arn\n"
        "  }\n"
        "  default_action {\n"
        '    type = "redirect"\n'
        "    redirect {\n"
        '      protocol = "HTTPS"\n'
        "    }\n"
        "  }\n"
        "}\n"
    ))
    assert any(f.rule == _RULE for f in findings)


def test_comment_containing_a_brace_does_not_truncate_top_level_scope(tmp_path: Path) -> None:
    # round-2 review H-3: a naive per-line brace tally in `top_level_attribute_text` let a `{`
    # inside a `#` comment above the real attributes look like an extra open brace, dropping
    # every top-level line below it -- the plaintext listener went silent. `protocol = "HTTP"`
    # here must still be read as top-level and fire.
    findings = _run(tmp_path, (
        'resource "aws_lb_listener" "front_end" {\n'
        "  load_balancer_arn = aws_lb.main.arn\n"
        "  # old note: was {\n"
        '  protocol          = "HTTP"\n'
        '  port              = "80"\n'
        "\n"
        "  default_action {\n"
        '    type             = "forward"\n'
        "    target_group_arn = aws_lb_target_group.main.arn\n"
        "  }\n"
        "}\n"
    ))
    assert any(f.rule == _RULE for f in findings)


def test_nested_https_protocol_is_not_mistaken_for_top_level(tmp_path: Path) -> None:
    # The resource's own top-level protocol is "HTTPS" (safe); a nested redirect block's own
    # protocol = "HTTP" must not be read as the listener's protocol (review H4a scoping).
    findings = _run(tmp_path, (
        'resource "aws_lb_listener" "front_end" {\n'
        "  load_balancer_arn = aws_lb.main.arn\n"
        '  port              = "443"\n'
        '  protocol          = "HTTPS"\n'
        "  ssl_policy        = \"ELBSecurityPolicy-TLS13-1-2-2021-06\"\n"
        "  certificate_arn   = aws_acm_certificate.main.arn\n"
        "\n"
        "  default_action {\n"
        '    type = "redirect"\n'
        "    redirect {\n"
        '      protocol = "HTTP"\n'
        "    }\n"
        "  }\n"
        "}\n"
    ))
    assert not any(f.rule == _RULE for f in findings)


def test_aws_alb_listener_alias_fires(tmp_path: Path) -> None:
    # aws_alb_listener is the older alias for aws_lb_listener (review H4c).
    findings = _run(tmp_path, (
        'resource "aws_alb_listener" "front_end" {\n'
        "  load_balancer_arn = aws_alb.main.arn\n"
        '  port              = "80"\n'
        '  protocol          = "HTTP"\n'
        "\n"
        "  default_action {\n"
        '    type             = "forward"\n'
        "    target_group_arn = aws_lb_target_group.main.arn\n"
        "  }\n"
        "}\n"
    ))
    assert any(f.rule == _RULE for f in findings)


def test_missing_protocol_silent(tmp_path: Path) -> None:
    findings = _run(tmp_path, (
        'resource "aws_lb_listener" "weird" {\n'
        "  load_balancer_arn = aws_lb.main.arn\n"
        '  port              = "80"\n'
        "\n"
        "  default_action {\n"
        '    type             = "forward"\n'
        "    target_group_arn = aws_lb_target_group.main.arn\n"
        "  }\n"
        "}\n"
    ))
    assert not any(f.rule == _RULE for f in findings)


def test_pragma_silences(tmp_path: Path) -> None:
    findings = _run(tmp_path, (
        'resource "aws_lb_listener" "front_end" {\n'
        "  load_balancer_arn = aws_lb.main.arn\n"
        '  port              = "80"\n'
        '  protocol          = "HTTP"  # security: allow-alb-http-listener\n'
        "\n"
        "  default_action {\n"
        '    type             = "forward"\n'
        "    target_group_arn = aws_lb_target_group.main.arn\n"
        "  }\n"
        "}\n"
    ))
    assert not any(f.rule == _RULE for f in findings)


def test_non_listener_resource_silent(tmp_path: Path) -> None:
    findings = _run(tmp_path, (
        'resource "aws_lb" "main" {\n'
        '  name               = "main"\n'
        '  internal           = false\n'
        '  load_balancer_type = "application"\n'
        "}\n"
    ))
    assert not any(f.rule == _RULE for f in findings)


def test_applies_gate(tmp_path: Path) -> None:
    guard = AlbListenerHttpProtocolGuard()
    assert guard.applies(mkprofile(tmp_path, features=set())) is False


def test_applies_with_terraform(tmp_path: Path) -> None:
    guard = AlbListenerHttpProtocolGuard()
    assert guard.applies(_tf_prof(tmp_path)) is True


def _redirect_listener(host_line: str, target_protocol: str) -> str:
    return (
        'resource "aws_lb_listener" "front_end" {\n'
        "  load_balancer_arn = aws_lb.main.arn\n"
        '  port              = "80"\n'
        '  protocol          = "HTTP"\n'
        "  default_action {\n"
        '    type = "redirect"\n'
        "    redirect {\n"
        f"{host_line}"
        '      port        = "443"\n'
        f'      protocol    = "{target_protocol}"\n'
        '      status_code = "HTTP_301"\n'
        "    }\n"
        "  }\n"
        "}\n"
    )


def test_redirect_with_interpolated_host_stays_silent(tmp_path: Path) -> None:
    # PR #1162 round-2 M-2: `host = "${var.host}"` inside the redirect used to end the
    # `[^{}]*` redirect regex at the interpolation's `}`, so an HTTPS redirect listener fired.
    content = _redirect_listener('      host        = "${var.host}"\n', "HTTPS")
    assert not any(f.rule == _RULE for f in _run(tmp_path, content))


def test_redirect_to_plain_http_with_interpolated_host_still_fires(tmp_path: Path) -> None:
    # The direction the interpolation fix trades against: a redirect that stays on HTTP is not
    # the hardened pattern, interpolation or not.
    content = _redirect_listener('      host        = "${var.host}"\n', "HTTP")
    assert [f.rule for f in _run(tmp_path, content)] == [_RULE]


def test_protocol_written_only_in_a_comment_is_not_the_listener_protocol(tmp_path: Path) -> None:
    # A commented-out `protocol = "HTTP"` above a real HTTPS protocol is not a plaintext
    # listener...
    commented = (
        'resource "aws_lb_listener" "front_end" {\n'
        "  load_balancer_arn = aws_lb.main.arn\n"
        '  # protocol        = "HTTP"\n'
        '  protocol          = "HTTPS"\n'
        "  certificate_arn   = aws_acm_certificate.main.arn\n"
        "  default_action {\n"
        '    type             = "forward"\n'
        "    target_group_arn = aws_lb_target_group.main.arn\n"
        "  }\n"
        "}\n"
    )
    assert not any(f.rule == _RULE for f in _run(tmp_path, commented))
    # ...while a real HTTP protocol with a trailing comment still fires.
    real = commented.replace('  # protocol        = "HTTP"\n', "").replace(
        '"HTTPS"\n', '"HTTP"  # plaintext hop, see ticket\n'
    )
    assert [f.rule for f in _run(tmp_path, real)] == [_RULE]
