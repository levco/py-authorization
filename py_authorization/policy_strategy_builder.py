from __future__ import annotations

from typing import Any, Callable, Type

from .policy import Strategy
from .policy_strategy import PolicyStrategy

StrategyMapper = dict[str, Type[PolicyStrategy[Any]]]


class PolicyStrategyBuilder:
    def __init__(self, strategy_mapper_callable: Callable[[], StrategyMapper]):
        self.strategy_mapper_callable = strategy_mapper_callable

    def build(self, strategy: Strategy) -> PolicyStrategy[Any] | None:
        strategy_class = self.strategy_mapper_callable().get(strategy.name)
        if not strategy_class:
            return None
        return strategy_class(strategy.args if strategy.args else dict())
