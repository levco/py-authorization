from typing import Optional, Type

from .policy import Strategy
from .policy_strategy import PolicyStrategy

StrategyMapper = dict[str, Type[PolicyStrategy]]


class PolicyStrategyBuilder:
    def __init__(self, strategies_mapper: StrategyMapper):
        self.strategies_mapper = strategies_mapper

    def build(self, strategy: Strategy) -> Optional[PolicyStrategy]:
        strategy_class = self.strategies_mapper.get(strategy.name)
        if not strategy_class:
            return None
        return strategy_class(strategy.args if strategy.args else dict())
