from __future__ import annotations

from agentsec.guards.session_fixation_no_regenerate import SessionFixationNoRegenerateGuard
from tests.guards._common import *  # noqa: F401,F403


def test_session_fixation_fires_without_regenerate(tmp_path: Path) -> None:
    (tmp_path / "auth.js").write_text(
        "app.post('/login', (req, res) => {\n"
        "  const user = authenticate(req.body.username, req.body.password);\n"
        "  req.session.userId = user.id;\n"
        "  res.json({ ok: true });\n"
        "});\n",
        encoding="utf-8",
    )
    findings = SessionFixationNoRegenerateGuard().run(tmp_path, mkprofile(tmp_path, features={"express"}))
    assert len(findings) == 1
    assert findings[0].rule == "session-fixation-no-regenerate/login-writes-session-without-regenerate"
    assert findings[0].severity == "medium"


def test_session_fixation_silent_when_regenerate_called(tmp_path: Path) -> None:
    (tmp_path / "auth.js").write_text(
        "app.post('/login', (req, res) => {\n"
        "  const user = authenticate(req.body.username, req.body.password);\n"
        "  req.session.regenerate((err) => {\n"
        "    req.session.userId = user.id;\n"
        "    res.json({ ok: true });\n"
        "  });\n"
        "});\n",
        encoding="utf-8",
    )
    assert SessionFixationNoRegenerateGuard().run(tmp_path, mkprofile(tmp_path, features={"express"})) == []


def test_session_fixation_silent_on_router_receiver(tmp_path: Path) -> None:
    # True positive: any receiver name (router, not just app) is matched.
    (tmp_path / "auth.js").write_text(
        "router.post('/api/login', (req, res) => {\n"
        "  req.session.userId = req.body.id;\n"
        "  res.json({ ok: true });\n"
        "});\n",
        encoding="utf-8",
    )
    findings = SessionFixationNoRegenerateGuard().run(tmp_path, mkprofile(tmp_path, features={"express"}))
    assert len(findings) == 1


def test_session_fixation_silent_no_session_write(tmp_path: Path) -> None:
    # FP-bait: a login route that never writes req.session at all (e.g. stateless JWT issuance).
    (tmp_path / "auth.js").write_text(
        "app.post('/login', (req, res) => {\n"
        "  const user = authenticate(req.body.username, req.body.password);\n"
        "  const token = issueJwt(user);\n"
        "  res.json({ token });\n"
        "});\n",
        encoding="utf-8",
    )
    assert SessionFixationNoRegenerateGuard().run(tmp_path, mkprofile(tmp_path, features={"express"})) == []


def test_session_fixation_silent_on_non_login_route(tmp_path: Path) -> None:
    # FP-bait: an unrelated route writing to req.session (e.g. a shopping cart) is not a login.
    (tmp_path / "cart.js").write_text(
        "app.post('/cart/add', (req, res) => {\n"
        "  req.session.cart = req.body.items;\n"
        "  res.json({ ok: true });\n"
        "});\n",
        encoding="utf-8",
    )
    assert SessionFixationNoRegenerateGuard().run(tmp_path, mkprofile(tmp_path, features={"express"})) == []


def test_session_fixation_pragma_silences(tmp_path: Path) -> None:
    (tmp_path / "auth.js").write_text(
        "app.post('/login', (req, res) => {  // security: allow-session-fixation\n"
        "  req.session.userId = req.body.id;\n"
        "  res.json({ ok: true });\n"
        "});\n",
        encoding="utf-8",
    )
    assert SessionFixationNoRegenerateGuard().run(tmp_path, mkprofile(tmp_path, features={"express"})) == []


def test_session_fixation_does_not_apply_without_express(tmp_path: Path) -> None:
    profile = mkprofile(tmp_path, features={"python", "fastapi"})
    assert SessionFixationNoRegenerateGuard().applies(profile) is False
    assert SessionFixationNoRegenerateGuard().run(tmp_path, profile) == []
