from unittest.mock import Mock

from assertpy import assert_that

from py_authorization import Authorization, Policy
from py_authorization.user import User


class Action:
    READ = "read"
    CREATE = "create"
    UPDATE = "update"


class Role:
    ADMIN = "admin"
    EDITOR = "editor"
    VIEWER = "viewer"


wildcard_policy = Policy(name="Wildcard", resources=["*"], roles=["*"], actions=["*"])

viewer_policy = Policy(
    name="Viewer policy", resources=["*"], roles=[Role.VIEWER], actions=[Action.READ]
)

form_policy = Policy(
    name="form policy", resources=["Form"], roles=[Role.ADMIN], actions=["*"]
)

update_policy = Policy(
    name="update policy",
    resources=["Deal"],
    roles=[Role.EDITOR, Role.ADMIN],
    actions=[Action.UPDATE],
)


def test_find_wildcard_policy() -> None:
    authorization = Authorization(
        policies=[wildcard_policy], strategy_mapper_callable=Mock(return_value={})
    )
    user = User(role=Role.ADMIN, id=None)

    resp = authorization._get_policy(
        user=user,
        resource_to_access="Form",
        action=Action.READ,
        sub_action=None,
    )

    assert_that(resp).is_equal_to(wildcard_policy)


def test_find_viewer_policy() -> None:
    authorization = Authorization(
        policies=[viewer_policy, wildcard_policy],
        strategy_mapper_callable=Mock(return_value={}),
    )
    user = User(role=Role.VIEWER, id=None)

    resp = authorization._get_policy(
        user=user,
        resource_to_access="Form",
        action=Action.READ,
        sub_action=None,
    )

    assert_that(resp).is_equal_to(viewer_policy)


def test_find_no_policy_when_role_doesnt_match() -> None:
    authorization = Authorization(
        policies=[viewer_policy], strategy_mapper_callable=Mock(return_value={})
    )
    user = User(role=Role.EDITOR, id=None)

    resp = authorization._get_policy(
        user=user,
        resource_to_access="Form",
        action=Action.READ,
        sub_action=None,
    )

    assert_that(resp).is_none()


def test_find_form_policy() -> None:
    authorization = Authorization(
        policies=[form_policy, viewer_policy, wildcard_policy],
        strategy_mapper_callable=Mock(return_value={}),
    )
    user = User(role=Role.ADMIN, id=None)

    resp = authorization._get_policy(
        user=user,
        resource_to_access="Form",
        action=Action.READ,
        sub_action=None,
    )

    assert_that(resp).is_equal_to(form_policy)


def test_find_no_policy_when_resource_is_not_found() -> None:
    authorization = Authorization(
        policies=[form_policy], strategy_mapper_callable=Mock(return_value={})
    )
    user = User(role=Role.ADMIN, id=None)

    resp = authorization._get_policy(
        user=user,
        resource_to_access="Submissions",
        action=Action.READ,
        sub_action=None,
    )

    assert_that(resp).is_none()


def test_find_update_policy() -> None:
    authorization = Authorization(
        policies=[update_policy, wildcard_policy],
        strategy_mapper_callable=Mock(return_value={}),
    )
    user = User(role=Role.EDITOR, id=None)

    resp = authorization._get_policy(
        user=user,
        resource_to_access="Form",
        action=Action.UPDATE,
        sub_action=None,
    )

    assert_that(resp).is_equal_to(resp)
