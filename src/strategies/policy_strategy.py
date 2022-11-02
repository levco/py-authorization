from sqlalchemy.orm.query import Query

from src.models.context import Context
from .ipolicy_strategy import IPolicyStrategy


class PolicyStrategy(IPolicyStrategy):
    def __init__(self, args):
        self.args = args

    def apply_policies_to_entity(self, entity, context: Context):
        raise NotImplementedError(f"{context.policy.name} policy cannot be applied on entities")

    def apply_policies_to_query(self, query: Query, context: Context) -> Query:
        raise NotImplementedError(f"{context.policy.name} policy cannot be applied on queries")
