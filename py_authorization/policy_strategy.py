from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Generic, Optional, TypeVar

from sqlalchemy.orm.query import Query

from py_authorization.context import Context

T = TypeVar("T", bound=object)


class PolicyStrategy(ABC, Generic[T]):
    def __init__(self, args: dict[str, Any]) -> None:
        self.args = args

    @abstractmethod
    def apply_policies_to_entity(self, entity: T, context: Context) -> Optional[T]:
        pass

    @abstractmethod
    def apply_policies_to_query(self, query: Query[T], context: Context) -> Query[T]:
        pass
