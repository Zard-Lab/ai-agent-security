from __future__ import annotations

from agentsec.guards.response_model_set import ResponseModelSetGuard
from tests.guards._common import *  # noqa: F401,F403


def test_response_model_flags_raw_db_return(tmp_path: Path) -> None:
    (tmp_path / "r.py").write_text(
        '@app.get("/users/{id}")\n'
        "def get_user(id: int):\n"
        "    return db.query(User).filter(User.id == id).first()\n", encoding="utf-8"
    )
    findings = ResponseModelSetGuard().run(tmp_path, _fastapi_prof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "response-model-set/raw-db-object-returned"

def test_response_model_passes_when_model_set(tmp_path: Path) -> None:
    (tmp_path / "r.py").write_text(
        '@app.get("/users/{id}", response_model=UserOut)\n'
        "def get_user(id: int):\n"
        "    return db.query(User).first()\n", encoding="utf-8"
    )
    assert ResponseModelSetGuard().run(tmp_path, _fastapi_prof(tmp_path)) == []

def test_response_model_passes_multiline_model(tmp_path: Path) -> None:
    (tmp_path / "r.py").write_text(
        "@app.get(\n"
        '    "/users",\n'
        "    response_model=list[UserOut],\n"
        ")\n"
        "def list_users():\n"
        "    return db.query(User).all()\n", encoding="utf-8"
    )
    assert ResponseModelSetGuard().run(tmp_path, _fastapi_prof(tmp_path)) == []

def test_response_model_ignores_dict_and_projection(tmp_path: Path) -> None:
    (tmp_path / "a.py").write_text('@app.get("/health")\ndef health():\n    return {"ok": True}\n', encoding="utf-8")
    (tmp_path / "b.py").write_text(
        '@app.get("/users")\ndef ls():\n    return [UserOut.from_orm(u) for u in users]\n', encoding="utf-8"
    )
    assert ResponseModelSetGuard().run(tmp_path, _fastapi_prof(tmp_path)) == []

def test_response_model_ignores_non_route_helper(tmp_path: Path) -> None:
    (tmp_path / "h.py").write_text("def helper():\n    return db.query(User).all()\n", encoding="utf-8")
    assert ResponseModelSetGuard().run(tmp_path, _fastapi_prof(tmp_path)) == []

def test_response_model_na_without_fastapi() -> None:
    assert ResponseModelSetGuard().applies(mkprofile(Path("/tmp"), features={"python"})) is False

def test_response_model_docstring_example_silent(tmp_path: Path) -> None:
    # Precision fix: an anti-pattern example inside a docstring should not fire.
    (tmp_path / "guide.py").write_text(
        '"""Example anti-pattern — do NOT do this:\n'
        "\n"
        "@app.get('/items')\n"
        "async def get_items():\n"
        "    return db.query(Item).all()  # BAD - exposes every column\n"
        '"""\n'
        "def some_real_function() -> None:\n"
        "    pass\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"fastapi"}, python_dirs=["."])
    assert ResponseModelSetGuard().run(tmp_path, profile) == []


# --- content sub-check (checklist 2b-excessive-data-exposure): a set response_model whose ---
# --- schema mirrors the ORM 1:1 is still an over-exposure, not a filtered-and-safe response. ---

def test_response_model_flags_sensitive_field_in_schema(tmp_path: Path) -> None:
    # Planted violation: response_model IS set (the presence-only check goes silent), but the
    # schema it points at re-declares an ORM-internal field.
    (tmp_path / "r.py").write_text(
        "from pydantic import BaseModel\n"
        "\n"
        "class UserOut(BaseModel):\n"
        "    id: int\n"
        "    hashed_password: str\n"
        "\n"
        '@app.get("/users/{id}", response_model=UserOut)\n'
        "def get_user(id: int):\n"
        "    return db.query(User).first()\n",
        encoding="utf-8",
    )
    findings = ResponseModelSetGuard().run(tmp_path, _fastapi_prof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "response-model-set/sensitive-field-in-response-model"
    assert findings[0].severity == "high"

def test_response_model_ignores_token_response_schema(tmp_path: Path) -> None:
    # FP-bait: an OAuth2 token-issuance response schema legitimately carries access_token /
    # refresh_token / token_type. Must stay silent (token stems are deliberately excluded).
    (tmp_path / "r.py").write_text(
        "from pydantic import BaseModel\n"
        "\n"
        "class TokenResponse(BaseModel):\n"
        "    access_token: str\n"
        "    refresh_token: str\n"
        "    token_type: str\n"
        "\n"
        '@app.post("/token", response_model=TokenResponse)\n'
        "def login():\n"
        "    return db.query(Token).first()\n",
        encoding="utf-8",
    )
    assert ResponseModelSetGuard().run(tmp_path, _fastapi_prof(tmp_path)) == []

def test_response_model_ignores_boolean_password_flag(tmp_path: Path) -> None:
    # FP-bait (review H7): `has_password: bool` is a flag about whether a password is set, not
    # the password itself — an ordinary public profile field.
    (tmp_path / "r.py").write_text(
        "from pydantic import BaseModel\n"
        "\n"
        "class UserOut(BaseModel):\n"
        "    id: int\n"
        "    has_password: bool\n"
        "\n"
        '@app.get("/users/{id}", response_model=UserOut)\n'
        "def get_user(id: int):\n"
        "    return db.query(User).first()\n",
        encoding="utf-8",
    )
    assert ResponseModelSetGuard().run(tmp_path, _fastapi_prof(tmp_path)) == []

def test_response_model_ignores_password_changed_timestamp(tmp_path: Path) -> None:
    # FP-bait (review H7): `password_changed_at: datetime` is metadata about WHEN the password
    # last changed, not the password value itself — an ordinary public profile field.
    (tmp_path / "r.py").write_text(
        "from pydantic import BaseModel\n"
        "\n"
        "class UserOut(BaseModel):\n"
        "    id: int\n"
        "    password_changed_at: str\n"
        "\n"
        '@app.get("/users/{id}", response_model=UserOut)\n'
        "def get_user(id: int):\n"
        "    return db.query(User).first()\n",
        encoding="utf-8",
    )
    assert ResponseModelSetGuard().run(tmp_path, _fastapi_prof(tmp_path)) == []

def test_response_model_flags_password_hash_field(tmp_path: Path) -> None:
    # Narrowing must not overshoot: a field naming the actual sensitive value, even one with a
    # qualifier prefix/suffix that isn't the boolean-flag or timestamp-metadata shape, still fires.
    (tmp_path / "r.py").write_text(
        "from pydantic import BaseModel\n"
        "\n"
        "class UserOut(BaseModel):\n"
        "    id: int\n"
        "    password_hash: str\n"
        "\n"
        '@app.get("/users/{id}", response_model=UserOut)\n'
        "def get_user(id: int):\n"
        "    return db.query(User).first()\n",
        encoding="utf-8",
    )
    findings = ResponseModelSetGuard().run(tmp_path, _fastapi_prof(tmp_path))
    assert [f.rule for f in findings] == ["response-model-set/sensitive-field-in-response-model"]

def test_response_model_ignores_public_only_schema(tmp_path: Path) -> None:
    # FP-bait: a schema exposing only genuinely public fields must stay silent.
    (tmp_path / "r.py").write_text(
        "from pydantic import BaseModel\n"
        "\n"
        "class UserOut(BaseModel):\n"
        "    id: int\n"
        "    email: str\n"
        "    username: str\n"
        "\n"
        '@app.get("/users/{id}", response_model=UserOut)\n'
        "def get_user(id: int):\n"
        "    return db.query(User).first()\n",
        encoding="utf-8",
    )
    assert ResponseModelSetGuard().run(tmp_path, _fastapi_prof(tmp_path)) == []

def test_response_model_flags_sensitive_field_via_local_subclass(tmp_path: Path) -> None:
    # Bypass attempt: the sensitive field lives on a local base class, not on the response_model
    # class itself (`class UserOut(_UserBase)` where `_UserBase(BaseModel)` holds the field).
    (tmp_path / "r.py").write_text(
        "from pydantic import BaseModel\n"
        "\n"
        "class _UserBase(BaseModel):\n"
        "    hashed_password: str\n"
        "\n"
        "class UserOut(_UserBase):\n"
        "    id: int\n"
        "\n"
        '@app.get("/users/{id}", response_model=UserOut)\n'
        "def get_user(id: int):\n"
        "    return db.query(User).first()\n",
        encoding="utf-8",
    )
    findings = ResponseModelSetGuard().run(tmp_path, _fastapi_prof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "response-model-set/sensitive-field-in-response-model"

def test_response_model_flags_sensitive_field_via_alias(tmp_path: Path) -> None:
    # Bypass attempt: response_model= points at a bare-identifier alias of the real schema class,
    # not the class name directly.
    (tmp_path / "r.py").write_text(
        "from pydantic import BaseModel\n"
        "\n"
        "class UserOut(BaseModel):\n"
        "    hashed_password: str\n"
        "\n"
        "UserSchema = UserOut\n"
        "\n"
        '@app.get("/users/{id}", response_model=UserSchema)\n'
        "def get_user(id: int):\n"
        "    return db.query(User).first()\n",
        encoding="utf-8",
    )
    findings = ResponseModelSetGuard().run(tmp_path, _fastapi_prof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "response-model-set/sensitive-field-in-response-model"

def test_response_model_sensitive_field_pragma_suppresses(tmp_path: Path) -> None:
    # A reviewed, intentional field is suppressible per-field, same convention as the
    # presence-only check's `allow-no-response-model` pragma.
    (tmp_path / "r.py").write_text(
        "from pydantic import BaseModel\n"
        "\n"
        "class UserOut(BaseModel):\n"
        "    id: int\n"
        "    hashed_password: str  # security: allow-sensitive-response-field\n"
        "\n"
        '@app.get("/users/{id}", response_model=UserOut)\n'
        "def get_user(id: int):\n"
        "    return db.query(User).first()\n",
        encoding="utf-8",
    )
    assert ResponseModelSetGuard().run(tmp_path, _fastapi_prof(tmp_path)) == []

def test_response_model_cross_file_schema_stays_silent(tmp_path: Path) -> None:
    # Documented limitation: a response_model resolved to a class defined in a DIFFERENT file is
    # out of scope for this pass — silent, not a false "safe" claim (see the module docstring).
    # A REAL two-file fixture (schema in schemas.py, route in routers/users.py) — the majority
    # FastAPI layout — so this proves the guard doesn't accidentally resolve cross-file, not just
    # that it stays silent because the import target doesn't exist anywhere at all (review M5).
    # The schema DOES carry a sensitive field, so a false "safe" would surface as a real miss.
    (tmp_path / "schemas.py").write_text(
        "from pydantic import BaseModel\n"
        "\n"
        "class UserOut(BaseModel):\n"
        "    id: int\n"
        "    hashed_password: str\n",
        encoding="utf-8",
    )
    routers_dir = tmp_path / "routers"
    routers_dir.mkdir()
    (routers_dir / "users.py").write_text(
        "from schemas import UserOut\n"
        "\n"
        '@app.get("/users/{id}", response_model=UserOut)\n'
        "def get_user(id: int):\n"
        "    return db.query(User).first()\n",
        encoding="utf-8",
    )
    assert ResponseModelSetGuard().run(tmp_path, _fastapi_prof(tmp_path)) == []



def test_response_model_ignores_password_reset_requested_flag(tmp_path: Path) -> None:
    # FP-bait (round-4 review F3): `password_reset_requested: bool` is a boolean about the STATE
    # of a credential — the same category as `has_password`, just written as a trailing
    # participle instead of a leading flag-word. It carries no credential value.
    (tmp_path / "r.py").write_text(
        "from pydantic import BaseModel\n"
        "\n"
        "class UserOut(BaseModel):\n"
        "    id: int\n"
        "    password_reset_requested: bool\n"
        "\n"
        '@app.get("/users/{id}", response_model=UserOut)\n'
        "def get_user(id: int):\n"
        "    return db.query(User).first()\n",
        encoding="utf-8",
    )
    assert ResponseModelSetGuard().run(tmp_path, _fastapi_prof(tmp_path)) == []


def test_response_model_flags_password_reset_token(tmp_path: Path) -> None:
    # The direction traded against by F3's narrowing: a password-reset TOKEN *is* a credential,
    # and `password_reset` is only benign when it ends in a state participle. This is the
    # neighbour the closed suffix list exists to protect — it must still fire.
    (tmp_path / "r.py").write_text(
        "from pydantic import BaseModel\n"
        "\n"
        "class UserOut(BaseModel):\n"
        "    id: int\n"
        "    password_reset_token: str\n"
        "\n"
        '@app.get("/users/{id}", response_model=UserOut)\n'
        "def get_user(id: int):\n"
        "    return db.query(User).first()\n",
        encoding="utf-8",
    )
    findings = ResponseModelSetGuard().run(tmp_path, _fastapi_prof(tmp_path))
    assert [f.rule for f in findings] == ["response-model-set/sensitive-field-in-response-model"]


def test_response_model_missing_pragma_comment_suppresses_and_a_string_does_not(tmp_path: Path) -> None:
    # #1040: `allow-no-response-model` counts only as a real comment on the return line; the
    # phrase quoted in a string there is not one (neutral run = control).
    route = '@app.get("/users/{id}")\ndef get_user(id: int):\n    return db.query(User).first()'
    for tail, n in (
        ('; _note = "# reviewed"', 1),
        ('; _note = "# security: allow-no-response-model"', 1),
        ("  # security: allow-no-response-model", 0),
    ):
        (tmp_path / "r.py").write_text(f"{route}{tail}\n", encoding="utf-8")
        findings = ResponseModelSetGuard().run(tmp_path, _fastapi_prof(tmp_path))
        assert [f.rule for f in findings] == ["response-model-set/raw-db-object-returned"] * n, tail


def test_response_model_sensitive_field_pragma_quoted_in_a_string_still_fires(tmp_path: Path) -> None:
    # #1040: the per-field pragma quoted in a string on the field line (its default) is not a comment.
    for note in ("# reviewed", "# security: allow-sensitive-response-field"):
        (tmp_path / "r.py").write_text(
            "from pydantic import BaseModel\n"
            "\n"
            "class UserOut(BaseModel):\n"
            "    id: int\n"
            f'    hashed_password: str = "{note}"\n'
            "\n"
            '@app.get("/users/{id}", response_model=UserOut)\n'
            "def get_user(id: int):\n"
            "    return db.query(User).first()\n",
            encoding="utf-8",
        )
        findings = ResponseModelSetGuard().run(tmp_path, _fastapi_prof(tmp_path))
        assert [f.rule for f in findings] == ["response-model-set/sensitive-field-in-response-model"], note


# A form feed is a line break to `str.splitlines()` but not to Python; inside a docstring the
# stripper blanks it, so a pragma set numbered on the raw text lands one line low (#1132 review, H1).
_FF_DOCSTRING = f'"""doc{chr(12)}x\nmore"""\n'


def test_response_model_both_pragmas_after_a_form_feed_docstring_stay_on_their_own_line(tmp_path: Path) -> None:
    def rules(source: str) -> list[str]:
        (tmp_path / "r.py").write_text(_FF_DOCSTRING + source, encoding="utf-8")
        return [f.rule for f in ResponseModelSetGuard().run(tmp_path, _fastapi_prof(tmp_path))]

    route = '@app.get("/users/{id}")\ndef get_user(id: int):\n    return db.query(User).first()'
    assert rules(f"{route}\n") == ["response-model-set/raw-db-object-returned"]  # control
    assert rules(f"{route}  # security: allow-no-response-model\n") == []

    def model(field_tail: str) -> str:
        return (
            "from pydantic import BaseModel\n\nclass UserOut(BaseModel):\n    id: int\n"
            f"    hashed_password: str{field_tail}\n\n"
            '@app.get("/users/{id}", response_model=UserOut)\n'
            "def get_user(id: int):\n    return db.query(User).first()\n"
        )

    assert rules(model("")) == ["response-model-set/sensitive-field-in-response-model"]  # control
    assert rules(model("  # security: allow-sensitive-response-field")) == []
