from abc import ABC, abstractmethod

from sqlalchemy.orm.query import Query

from src.models.context import Context


class IPolicyStrategy(ABC):
    @abstractmethod
    def __init__(self, args) -> None:
        pass

    @abstractmethod
    def apply_policies_to_entity(self, entity, context: Context):
        pass

    @abstractmethod
    def apply_policies_to_query(self, query: Query, context: Context) -> Query:
        pass
