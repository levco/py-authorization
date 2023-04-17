from typing import Optional, TypeVar, cast
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
    ADMIN = "admin"
    VIEWER = "viewer"


admin_policy = Policy(
    name="Admin",
    resources=["*"],
    roles=[Role.ADMIN],
    actions=["*"],
)

strategy_policy = Policy(
    name="Strategy",
    resources=["Form"],
    roles=[Role.VIEWER],
    actions=[Action.READ],
    strategies=[Strategy("TestStrategy")],
)


def test_authorization_evaluates_simple_policy() -> None:
    authorization = Authorization(
        policies=[admin_policy], strategy_mapper_callable=Mock(return_value={})
    )
    form = Mock()
    user = User(role=Role.ADMIN, id=None)
    resp = authorization.apply_policies_to_one(
        user=user,
        entity=form,
        resource_to_check="Form",
        action=Action.CREATE,
    )

    assert_that(resp).is_equal_to(form)


def test_authorization_evaluates_simple_policy_and_rejects_the_object() -> None:
    authorization = Authorization(
        policies=[admin_policy], strategy_mapper_callable=Mock(return_value={})
    )
    form = Mock()
    user = User(role=Role.VIEWER, id=None)

    resp = authorization.apply_policies_to_one(
        user=user,
        entity=form,
        resource_to_check="Form",
        action=Action.CREATE,
    )

    assert_that(resp).is_none()


def test_authorization_evaluates_simple_policy_multiple_objects() -> None:
    authorization = Authorization(
        policies=[admin_policy], strategy_mapper_callable=Mock(return_value={})
    )
    forms = [Mock(), Mock()]
    user = User(role=Role.ADMIN, id=None)

    resp = authorization.apply_policies_to_many(
        user=user,
        entities=forms,
        resource_to_check="Form",
        action=Action.CREATE,
    )

    assert_that(resp).is_equal_to(forms)


def test_authorization_evaluates_simple_policy_and_reject_multiple_objects() -> None:
    authorization = Authorization(
        policies=[admin_policy], strategy_mapper_callable=Mock(return_value={})
    )
    forms = [Mock(), Mock()]
    user = User(role=Role.VIEWER, id=None)

    resp = authorization.apply_policies_to_many(
        user=user,
        entities=forms,
        resource_to_check="Form",
        action=Action.CREATE,
    )

    assert_that(resp).is_empty()


def test_authorization_applies_policy_with_strategy() -> None:
    class TestStrategy(PolicyStrategy):
        def apply_policies_to_entity(self, entity: T, context: Context) -> Optional[T]:
            mock = cast(Mock, entity)
            return mock if mock.id == 2 else None

    strategy_mapper: StrategyMapper = {"TestStrategy": TestStrategy}
    authorization = Authorization(
        policies=[strategy_policy],
        strategy_mapper_callable=Mock(return_value=strategy_mapper),
    )

    forms = [Mock(id=1), Mock(id=2)]
    user = User(role=Role.VIEWER, id=None)

    resp = authorization.apply_policies_to_many(
        user=user,
        entities=forms,
        resource_to_check="Form",
        action=Action.READ,
    )

    assert_that(resp).is_length(1)
    assert_that(resp[0].id).is_equal_to(2)


def test_authorization_applies_policy_with_strategy_to_one_object() -> None:
    class TestStrategy(PolicyStrategy):
        def apply_policies_to_entity(self, entity: T, context: Context) -> Optional[T]:
            mock = cast(Mock, entity)
            return mock if mock.id == 2 else None

    strategy_mapper: StrategyMapper = {"TestStrategy": TestStrategy}
    authorization = Authorization(
        policies=[admin_policy],
        strategy_mapper_callable=Mock(return_value=strategy_mapper),
    )
    form = Mock()
    user = User(role=Role.ADMIN, id=None)

    resp = authorization.apply_policies_to_one(
        user=user,
        entity=form,
        resource_to_check="Form",
        action=Action.CREATE,
    )

    assert_that(resp).is_equal_to(form)


def test_authorization_evaluates_simple_policy_query() -> None:
    authorization = Authorization(
        policies=[admin_policy], strategy_mapper_callable=Mock(return_value={})
    )
    query = Mock()
    user = User(role=Role.ADMIN, id=None)

    resp = authorization.apply_policies_to_query(
        user=user,
        query=query,
        action=Action.CREATE,
        resources_to_check=["Form"],
    )

    assert_that(resp).is_equal_to(query)


def test_authorization_evaluates_simple_policy_query_and_apply_empty_filter_when_is_rejected() -> (
    None
):
    authorization = Authorization(
        policies=[admin_policy], strategy_mapper_callable=Mock(return_value={})
    )
    query = Mock()
    user = User(role=Role.VIEWER, id=None)

    resp = authorization.apply_policies_to_query(
        user=user,
        query=query,
        action=Action.CREATE,
        resources_to_check=["Form"],
    )

    assert_that(resp).is_not_equal_to(query)
    query.filter.assert_called_once_with(False)


def test_authorization_applies_policy_with_strategy_to_query() -> None:
    class TestStrategy(PolicyStrategy):
        def apply_policies_to_query(self, query: Query, context: Context) -> Query:
            query.filter("test_filter")

    strategy_mapper: StrategyMapper = {"TestStrategy": TestStrategy}
    authorization = Authorization(
        policies=[strategy_policy],
        strategy_mapper_callable=Mock(return_value=strategy_mapper),
    )
    query = Mock()
    user = User(role=Role.VIEWER, id=None)

    authorization.apply_policies_to_query(
        user=user,
        query=query,
        action=Action.READ,
        resources_to_check=["Form"],
    )

    query.filter.assert_called_once_with("test_filter")
