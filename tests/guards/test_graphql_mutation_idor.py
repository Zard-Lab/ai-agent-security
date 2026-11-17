from __future__ import annotations

import pytest

from agentsec.guards.graphql_mutation_idor import GraphqlMutationIdorGuard
from tests.guards._common import *  # noqa: F401,F403


def _prof(root: Path) -> StackProfile:
    return mkprofile(root, features={"python", "graphql"})


def test_flags_unscoped_strawberry_mutation(tmp_path: Path) -> None:
    (tmp_path / "bookings.py").write_text(
        "import strawberry\n\n\n"
        "@strawberry.type\n"
        "class Mutation:\n"
        "    @strawberry.mutation\n"
        "    def cancel_reservation(self, reservation_id: str) -> bool:\n"
        "        reservation = Reservation.query.get(reservation_id)\n"
        "        reservation.status = 'cancelled'\n"
        "        return True\n",
        encoding="utf-8",
    )
    findings = GraphqlMutationIdorGuard().run(tmp_path, _prof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "graphql-mutation-idor/unscoped-mutation"
    assert findings[0].severity == "high"
    assert "OWASP:A01" in findings[0].standards


def test_flags_unscoped_ariadne_mutation(tmp_path: Path) -> None:
    (tmp_path / "bookings.py").write_text(
        "from ariadne import MutationType\n\n"
        "mutation = MutationType()\n\n"
        "@mutation.field('cancelReservation')\n"
        "def resolve_cancel_reservation(_, info, reservation_id):\n"
        "    reservation = Reservation.query.get(reservation_id)\n"
        "    reservation.status = 'cancelled'\n"
        "    return True\n",
        encoding="utf-8",
    )
    findings = GraphqlMutationIdorGuard().run(tmp_path, _prof(tmp_path))
    assert len(findings) == 1


def _ariadne_resolver(receiver: str) -> str:
    """An otherwise-identical vulnerable Ariadne resolver bound to `receiver`.

    Everything except the decorator's receiver name is held constant, so a test using this
    isolates the receiver match and nothing else."""
    return (
        "from ariadne import MutationType\n\n"
        f"{receiver} = MutationType()\n\n"
        f"@{receiver}.field('cancelReservation')\n"
        "def resolve_cancel_reservation(_, info, reservation_id):\n"
        "    reservation = Reservation.query.get(reservation_id)\n"
        "    reservation.status = 'cancelled'\n"
        "    return True\n"
    )


@pytest.mark.parametrize(
    "receiver",
    ["mutation", "mutation_type", "Mutation", "root_mutation", "admin_mutation_type"],
)
def test_ariadne_receiver_naming_conventions_still_fire(tmp_path: Path, receiver: str) -> None:
    r"""The receiver anchor is a NARROWING, so the vulnerable case must still fire under every
    real Ariadne binding convention — including the `_`-separated prefix (`root_mutation`) that a
    both-sides `\b` anchor would have wrongly rejected."""
    (tmp_path / "bookings.py").write_text(_ariadne_resolver(receiver), encoding="utf-8")
    assert len(GraphqlMutationIdorGuard().run(tmp_path, _prof(tmp_path))) == 1


@pytest.mark.parametrize("receiver", ["permutation_type", "commutation_check", "my_permutation"])
def test_receiver_merely_containing_mutation_is_not_an_ariadne_mutation(
    tmp_path: Path, receiver: str
) -> None:
    r"""FP-bait for the receiver anchor: a binding whose name merely CONTAINS "mutation" is an
    ordinary object, not an Ariadne mutation type. Before the anchor the unanchored `\w*mutation\w*`
    matched all three and reported a HIGH finding on ordinary code."""
    (tmp_path / "shuffle.py").write_text(_ariadne_resolver(receiver), encoding="utf-8")
    assert GraphqlMutationIdorGuard().run(tmp_path, _prof(tmp_path)) == []


def test_silent_on_ownership_check(tmp_path: Path) -> None:
    (tmp_path / "bookings.py").write_text(
        "import strawberry\n\n\n"
        "@strawberry.type\n"
        "class Mutation:\n"
        "    @strawberry.mutation\n"
        "    def cancel_reservation(self, info, reservation_id: str) -> bool:\n"
        "        reservation = Reservation.query.filter_by(\n"
        "            id=reservation_id, user_id=info.context.current_user.id\n"
        "        ).first()\n"
        "        reservation.status = 'cancelled'\n"
        "        return True\n",
        encoding="utf-8",
    )
    assert GraphqlMutationIdorGuard().run(tmp_path, _prof(tmp_path)) == []


def test_silent_on_query_field_not_mutation(tmp_path: Path) -> None:
    # A bare @strawberry.field is used for BOTH queries and mutations depending on which class it
    # decorates — the guard deliberately matches only the unambiguous @strawberry.mutation, since
    # telling a query field from a mutation field apart needs the enclosing class's own
    # declaration, which iter_functions's per-function block does not carry.
    (tmp_path / "bookings.py").write_text(
        "import strawberry\n\n\n"
        "@strawberry.type\n"
        "class Query:\n"
        "    @strawberry.field\n"
        "    def reservation(self, reservation_id: str):\n"
        "        return Reservation.query.get(reservation_id)\n",
        encoding="utf-8",
    )
    assert GraphqlMutationIdorGuard().run(tmp_path, _prof(tmp_path)) == []


def test_silent_without_id_param(tmp_path: Path) -> None:
    (tmp_path / "bookings.py").write_text(
        "import strawberry\n\n\n"
        "@strawberry.type\n"
        "class Mutation:\n"
        "    @strawberry.mutation\n"
        "    def cancel_all_expired(self) -> int:\n"
        "        return Reservation.query.filter_by(status='expired').delete()\n",
        encoding="utf-8",
    )
    assert GraphqlMutationIdorGuard().run(tmp_path, _prof(tmp_path)) == []


def test_silent_without_fetch(tmp_path: Path) -> None:
    (tmp_path / "bookings.py").write_text(
        "import strawberry\n\n\n"
        "@strawberry.type\n"
        "class Mutation:\n"
        "    @strawberry.mutation\n"
        "    def ping(self, reservation_id: str) -> bool:\n"
        "        return True\n",
        encoding="utf-8",
    )
    assert GraphqlMutationIdorGuard().run(tmp_path, _prof(tmp_path)) == []


def test_silent_on_non_mutation_function(tmp_path: Path) -> None:
    (tmp_path / "helpers.py").write_text(
        "def cancel_reservation(reservation_id):\n"
        "    reservation = Reservation.query.get(reservation_id)\n"
        "    reservation.status = 'cancelled'\n",
        encoding="utf-8",
    )
    assert GraphqlMutationIdorGuard().run(tmp_path, _prof(tmp_path)) == []


def test_pragma_suppresses(tmp_path: Path) -> None:
    (tmp_path / "bookings.py").write_text(
        "import strawberry\n\n\n"
        "@strawberry.type\n"
        "class Mutation:\n"
        "    @strawberry.mutation  # security: allow-unscoped-mutation\n"
        "    def cancel_reservation(self, reservation_id: str) -> bool:\n"
        "        reservation = Reservation.query.get(reservation_id)\n"
        "        reservation.status = 'cancelled'\n"
        "        return True\n",
        encoding="utf-8",
    )
    assert GraphqlMutationIdorGuard().run(tmp_path, _prof(tmp_path)) == []


def test_not_applies_without_graphql(tmp_path: Path) -> None:
    profile = mkprofile(tmp_path, features={"python"})
    assert not GraphqlMutationIdorGuard().applies(profile)


def test_not_applies_without_python(tmp_path: Path) -> None:
    profile = mkprofile(tmp_path, features={"graphql"})
    assert not GraphqlMutationIdorGuard().applies(profile)


def test_applies_with_python_and_graphql(tmp_path: Path) -> None:
    assert GraphqlMutationIdorGuard().applies(_prof(tmp_path))


def test_nonproduct_path_skipped(tmp_path: Path) -> None:
    d = tmp_path / "examples"
    d.mkdir(parents=True)
    (d / "bookings.py").write_text(
        "import strawberry\n\n\n"
        "@strawberry.type\n"
        "class Mutation:\n"
        "    @strawberry.mutation\n"
        "    def cancel_reservation(self, reservation_id: str) -> bool:\n"
        "        reservation = Reservation.query.get(reservation_id)\n"
        "        reservation.status = 'cancelled'\n"
        "        return True\n",
        encoding="utf-8",
    )
    assert GraphqlMutationIdorGuard().run(tmp_path, _prof(tmp_path)) == []


def test_graphql_mutation_idor_pragma_quoted_in_a_string_in_the_resolver_still_fires(tmp_path: Path) -> None:
    # #1040: the pragma phrase inside a string in the resolver block is not a comment, so it must not suppress.
    for note in ("# security: allow-unscoped-mutation", "# neutral note"):
        (tmp_path / "bookings.py").write_text(
            "import strawberry\n\n\n"
            "@strawberry.type\n"
            "class Mutation:\n"
            "    @strawberry.mutation\n"
            "    def cancel_reservation(self, reservation_id: str) -> bool:\n"
            f'        note = "{note}"\n'
            "        reservation = Reservation.query.get(reservation_id)\n"
            "        reservation.status = 'cancelled'\n"
            "        return True\n",
            encoding="utf-8",
        )
        findings = GraphqlMutationIdorGuard().run(tmp_path, _prof(tmp_path))
        assert [f.rule for f in findings] == ["graphql-mutation-idor/unscoped-mutation"], note
        assert findings[0].location.endswith("bookings.py:7")


def test_graphql_mutation_idor_pragma_in_a_sibling_resolver_does_not_suppress(tmp_path: Path) -> None:
    # #1040 reach: a real pragma comment ends at its own resolver block; the vulnerable sibling still fires.
    (tmp_path / "bookings.py").write_text(
        "import strawberry\n\n\n"
        "@strawberry.type\n"
        "class Mutation:\n"
        "    @strawberry.mutation\n"
        "    def archive_reservation(self, reservation_id: str) -> bool:\n"
        "        reservation = Reservation.query.get(reservation_id)\n"
        "        reservation.status = 'archived'\n"
        "        return True\n"
        "        # security: allow-unscoped-mutation\n"
        "\n"
        "    @strawberry.mutation\n"
        "    def cancel_reservation(self, reservation_id: str) -> bool:\n"
        "        reservation = Reservation.query.get(reservation_id)\n"
        "        reservation.status = 'cancelled'\n"
        "        return True\n",
        encoding="utf-8",
    )
    findings = GraphqlMutationIdorGuard().run(tmp_path, _prof(tmp_path))
    assert len(findings) == 1
    assert findings[0].location.endswith("bookings.py:14")
