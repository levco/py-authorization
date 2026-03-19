from typing import Any, Optional, TypeVar, cast
from unittest.mock import Mock

from assertpy import assert_that
from sqlalchemy.orm import Query

from py_authorization import (
    Authorization,
    Context,
    Policy,
    PolicyStrategy,
    Strategy,
    StrategyMapper,
)
from py_authorization.user import User

T = TypeVar("T", bound=object)


class Action:
    READ = "read"
    CREATE = "create"


class Role:
    BORROWER = "borrower"
    VIEWER = "viewer"


# ── Strategy implementations for testing ────────────────────────────


class AlwaysPassStrategy(PolicyStrategy):
    def apply_policies_to_entity(self, entity: T, context: Context) -> Optional[T]:
        return entity

    def apply_policies_to_query(self, query: Query, context: Context) -> Query:
        return query


class AlwaysFailStrategy(PolicyStrategy):
    def apply_policies_to_entity(self, entity: T, context: Context) -> Optional[T]:
        return None

    def apply_policies_to_query(self, query: Query, context: Context) -> Query:
        return query.filter(False)


class IdFilterStrategy(PolicyStrategy):
    """Passes only entities with id == 2."""

    def apply_policies_to_entity(self, entity: T, context: Context) -> Optional[T]:
        mock = cast(Mock, entity)
        return mock if mock.id == 2 else None

    def apply_policies_to_query(self, query: Query, context: Context) -> Query:
        return query


STRATEGY_MAPPER: StrategyMapper = {
    "AlwaysPass": AlwaysPassStrategy,
    "AlwaysFail": AlwaysFailStrategy,
    "IdFilter": IdFilterStrategy,
}


def _make_auth(policies: list[Policy]) -> Authorization:
    return Authorization(
        policies=policies,
        strategy_mapper_callable=Mock(return_value=STRATEGY_MAPPER),
    )


def _user(role: str = Role.BORROWER) -> User:
    return User(role=role, id=1)


# ═══════════════════════════════════════════════════════════════════
#  1a. or_strategies only — basic semantics
# ═══════════════════════════════════════════════════════════════════


def test_is_allowed_or_strategies_one_passes() -> None:
    policy = Policy(
        name="OR test",
        resources=["Form"],
        roles=[Role.BORROWER],
        actions=[Action.READ],
        or_strategies=[Strategy("AlwaysFail"), Strategy("AlwaysPass")],
    )
    auth = _make_auth([policy])
    assert_that(auth.is_allowed(user=_user(), action=Action.READ, resource="Form")).is_true()


def test_is_allowed_or_strategies_all_fail() -> None:
    policy = Policy(
        name="OR test",
        resources=["Form"],
        roles=[Role.BORROWER],
        actions=[Action.READ],
        or_strategies=[Strategy("AlwaysFail"), Strategy("AlwaysFail")],
    )
    auth = _make_auth([policy])
    assert_that(auth.is_allowed(user=_user(), action=Action.READ, resource="Form")).is_false()


def test_is_allowed_strategies_only_unchanged() -> None:
    policy = Policy(
        name="AND only",
        resources=["Form"],
        roles=[Role.BORROWER],
        actions=[Action.READ],
        strategies=[Strategy("AlwaysPass")],
    )
    auth = _make_auth([policy])
    assert_that(auth.is_allowed(user=_user(), action=Action.READ, resource="Form")).is_true()


# ═══════════════════════════════════════════════════════════════════
#  1b. Mixed AND + OR
# ═══════════════════════════════════════════════════════════════════


def test_is_allowed_and_passes_or_passes() -> None:
    policy = Policy(
        name="AND+OR pass",
        resources=["Form"],
        roles=[Role.BORROWER],
        actions=[Action.READ],
        strategies=[Strategy("AlwaysPass")],
        or_strategies=[Strategy("AlwaysPass")],
    )
    auth = _make_auth([policy])
    assert_that(auth.is_allowed(user=_user(), action=Action.READ, resource="Form")).is_true()


def test_is_allowed_and_fails_or_passes() -> None:
    policy = Policy(
        name="AND fail, OR pass",
        resources=["Form"],
        roles=[Role.BORROWER],
        actions=[Action.READ],
        strategies=[Strategy("AlwaysFail")],
        or_strategies=[Strategy("AlwaysPass")],
    )
    auth = _make_auth([policy])
    assert_that(auth.is_allowed(user=_user(), action=Action.READ, resource="Form")).is_false()


def test_is_allowed_and_passes_or_all_fail() -> None:
    policy = Policy(
        name="AND pass, OR fail",
        resources=["Form"],
        roles=[Role.BORROWER],
        actions=[Action.READ],
        strategies=[Strategy("AlwaysPass")],
        or_strategies=[Strategy("AlwaysFail")],
    )
    auth = _make_auth([policy])
    assert_that(auth.is_allowed(user=_user(), action=Action.READ, resource="Form")).is_false()


def test_is_allowed_neither_strategies() -> None:
    policy = Policy(
        name="No strategies",
        resources=["Form"],
        roles=[Role.BORROWER],
        actions=[Action.READ],
    )
    auth = _make_auth([policy])
    assert_that(auth.is_allowed(user=_user(), action=Action.READ, resource="Form")).is_true()


# ═══════════════════════════════════════════════════════════════════
#  1c. apply_policies_to_one
# ═══════════════════════════════════════════════════════════════════


def test_apply_to_one_or_strategies_one_passes() -> None:
    policy = Policy(
        name="OR to one",
        resources=["Form"],
        roles=[Role.BORROWER],
        actions=[Action.READ],
        or_strategies=[Strategy("AlwaysFail"), Strategy("AlwaysPass")],
    )
    auth = _make_auth([policy])
    entity = Mock(id=1)
    result = auth.apply_policies_to_one(
        user=_user(), entity=entity, resource_to_check="Form", action=Action.READ
    )
    assert_that(result).is_equal_to(entity)


def test_apply_to_one_or_strategies_all_fail() -> None:
    policy = Policy(
        name="OR to one fail",
        resources=["Form"],
        roles=[Role.BORROWER],
        actions=[Action.READ],
        or_strategies=[Strategy("AlwaysFail"), Strategy("AlwaysFail")],
    )
    auth = _make_auth([policy])
    entity = Mock(id=1)
    result = auth.apply_policies_to_one(
        user=_user(), entity=entity, resource_to_check="Form", action=Action.READ
    )
    assert_that(result).is_none()


def test_apply_to_one_and_plus_or() -> None:
    policy = Policy(
        name="AND+OR to one",
        resources=["Form"],
        roles=[Role.BORROWER],
        actions=[Action.READ],
        strategies=[Strategy("AlwaysPass")],
        or_strategies=[Strategy("AlwaysPass")],
    )
    auth = _make_auth([policy])
    entity = Mock(id=1)
    result = auth.apply_policies_to_one(
        user=_user(), entity=entity, resource_to_check="Form", action=Action.READ
    )
    assert_that(result).is_equal_to(entity)


def test_apply_to_one_and_fails_or_passes_denied() -> None:
    policy = Policy(
        name="AND fail OR pass",
        resources=["Form"],
        roles=[Role.BORROWER],
        actions=[Action.READ],
        strategies=[Strategy("AlwaysFail")],
        or_strategies=[Strategy("AlwaysPass")],
    )
    auth = _make_auth([policy])
    entity = Mock(id=1)
    result = auth.apply_policies_to_one(
        user=_user(), entity=entity, resource_to_check="Form", action=Action.READ
    )
    assert_that(result).is_none()


def test_apply_to_one_or_receives_original_entity() -> None:
    policy = Policy(
        name="OR original entity",
        resources=["Form"],
        roles=[Role.BORROWER],
        actions=[Action.READ],
        strategies=[Strategy("AlwaysPass")],
        or_strategies=[Strategy("IdFilter")],
    )
    auth = _make_auth([policy])

    entity_passes = Mock(id=2)
    result = auth.apply_policies_to_one(
        user=_user(), entity=entity_passes, resource_to_check="Form", action=Action.READ
    )
    assert_that(result).is_equal_to(entity_passes)

    entity_fails = Mock(id=1)
    result = auth.apply_policies_to_one(
        user=_user(), entity=entity_fails, resource_to_check="Form", action=Action.READ
    )
    assert_that(result).is_none()


# ═══════════════════════════════════════════════════════════════════
#  1d. apply_policies_to_many (polymorphic dispatch)
# ═══════════════════════════════════════════════════════════════════


def test_apply_to_many_filters_via_or_strategies() -> None:
    policy = Policy(
        name="OR to many",
        resources=["Form"],
        roles=[Role.BORROWER],
        actions=[Action.READ],
        or_strategies=[Strategy("IdFilter")],
    )
    auth = _make_auth([policy])
    entities = [Mock(id=1), Mock(id=2), Mock(id=3)]
    result = auth.apply_policies_to_many(
        user=_user(), entities=entities, resource_to_check="Form", action=Action.READ
    )
    assert_that(result).is_length(1)
    assert_that(result[0].id).is_equal_to(2)


# ═══════════════════════════════════════════════════════════════════
#  1e. apply_policies_to_query
# ═══════════════════════════════════════════════════════════════════


def test_query_no_strategies_returns_original_query() -> None:
    policy = Policy(
        name="No strat query",
        resources=["Form"],
        roles=[Role.BORROWER],
        actions=[Action.READ],
    )
    auth = _make_auth([policy])
    query = Mock()
    result = auth.apply_policies_to_query(
        user=_user(), query=query, action=Action.READ, resources_to_check=["Form"]
    )
    assert_that(result).is_equal_to(query)


def test_query_and_strategies_applied() -> None:
    policy = Policy(
        name="AND query",
        resources=["Form"],
        roles=[Role.BORROWER],
        actions=[Action.READ],
        strategies=[Strategy("AlwaysPass")],
    )
    auth = _make_auth([policy])
    query = Mock()
    auth.apply_policies_to_query(
        user=_user(), query=query, action=Action.READ, resources_to_check=["Form"]
    )


# ═══════════════════════════════════════════════════════════════════
#  Backwards compatibility
# ═══════════════════════════════════════════════════════════════════


def test_policy_without_or_strategies_defaults_to_none() -> None:
    policy = Policy(
        name="Legacy",
        resources=["Form"],
        roles=[Role.BORROWER],
        actions=[Action.READ],
        strategies=[Strategy("AlwaysPass")],
    )
    assert_that(policy.or_strategies).is_none()


def test_existing_and_only_behavior_unchanged() -> None:
    policy = Policy(
        name="AND only compat",
        resources=["Form"],
        roles=[Role.BORROWER],
        actions=[Action.READ],
        strategies=[Strategy("IdFilter")],
    )
    auth = _make_auth([policy])

    entity_pass = Mock(id=2)
    result = auth.apply_policies_to_one(
        user=_user(), entity=entity_pass, resource_to_check="Form", action=Action.READ
    )
    assert_that(result).is_equal_to(entity_pass)

    entity_fail = Mock(id=1)
    result = auth.apply_policies_to_one(
        user=_user(), entity=entity_fail, resource_to_check="Form", action=Action.READ
    )
    assert_that(result).is_none()


def test_deny_policy_still_denies_with_or_strategies() -> None:
    policy = Policy(
        name="Deny with OR",
        resources=["Form"],
        roles=[Role.BORROWER],
        actions=[Action.READ],
        or_strategies=[Strategy("AlwaysPass")],
        deny=True,
    )
    auth = _make_auth([policy])
    assert_that(auth.is_allowed(user=_user(), action=Action.READ, resource="Form")).is_false()

    entity = Mock(id=1)
    result = auth.apply_policies_to_one(
        user=_user(), entity=entity, resource_to_check="Form", action=Action.READ
    )
    assert_that(result).is_none()


def test_unknown_or_strategy_skipped_not_crash() -> None:
    policy = Policy(
        name="Unknown OR",
        resources=["Form"],
        roles=[Role.BORROWER],
        actions=[Action.READ],
        or_strategies=[Strategy("NonExistent"), Strategy("AlwaysPass")],
    )
    auth = _make_auth([policy])
    assert_that(auth.is_allowed(user=_user(), action=Action.READ, resource="Form")).is_true()


def test_all_unknown_or_strategies_denied() -> None:
    policy = Policy(
        name="All unknown OR",
        resources=["Form"],
        roles=[Role.BORROWER],
        actions=[Action.READ],
        or_strategies=[Strategy("NonExistent"), Strategy("AlsoNonExistent")],
    )
    auth = _make_auth([policy])
    assert_that(auth.is_allowed(user=_user(), action=Action.READ, resource="Form")).is_false()


def test_get_permissions_info_with_or_strategies() -> None:
    policy = Policy(
        name="OR info",
        resources=["Form"],
        roles=[Role.BORROWER],
        actions=[Action.READ],
        or_strategies=[Strategy("AlwaysPass")],
    )
    auth = _make_auth([policy])
    resp = auth.get_permissions_info(user=_user(), action=Action.READ, resource="Form")
    assert_that(resp.info).is_equal_to("Allowed but filtered.")
    assert_that(resp.allowed).is_false()
