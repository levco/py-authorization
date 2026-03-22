from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Generic, TypeVar

from sqlalchemy.orm.query import Query

from .context import Context


class EmptyEntity(object):
    """An empty entity is one that is passed as a fake entity to methods that ask for one but the current permission
    check doesn't require an entity to run.
    """

    pass


T = TypeVar("T", bound=object)


class PolicyStrategy(ABC, Generic[T]):
    def __init__(self, args: dict[str, Any]) -> None:
        self.args = args

    @abstractmethod
    def apply_policies_to_entity(self, entity: T | EmptyEntity, context: Context) -> T | None:
        pass

    @abstractmethod
    def apply_policies_to_query(self, query: Query[T], context: Context) -> Query[T]:
        pass
