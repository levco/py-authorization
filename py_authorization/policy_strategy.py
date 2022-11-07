from typing import Any, Optional, TypeVar

from py_authorization.context import Context
from sqlalchemy.orm.query import Query

T = TypeVar("T", bound=object)


class PolicyStrategy:
    def __init__(self, args: dict[str, Any]) -> None:
        self.args = args

    def apply_policies_to_entity(self, entity: Optional[T], context: Context) -> Optional[T]:
        raise NotImplementedError(f"{context.policy.name} policy cannot be applied on entities")

    def apply_policies_to_query(self, query: Query, context: Context) -> Query:
        raise NotImplementedError(f"{context.policy.name} policy cannot be applied on queries")
