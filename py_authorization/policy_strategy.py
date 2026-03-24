from typing import Any, Optional, TypeVar

from sqlalchemy.orm.query import Query

from py_authorization.context import Context

T = TypeVar("T", bound=object)


class PolicyStrategy:
    def __init__(self, args: dict[str, Any]) -> None:
        self.args = args

    def apply_policies_to_entity(self, entity: T, context: Context) -> Optional[T]:
        pass

    def apply_policies_to_query(self, query: Query, context: Context) -> Query:
        pass
