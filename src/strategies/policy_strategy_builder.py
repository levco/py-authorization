from strategies.ipolicy_strategy import IPolicyStrategy


class PolicyStrategyBuilder:
    def __init__(self, strategies_mapper):
        self.strategies_mapper = strategies_mapper

    def build(self, strategy: IPolicyStrategy):
        strategies = self.strategies_mapper.get_strategies()
        strategy_class = strategies.get(strategy.name)
        if not strategy_class:
            return
        return strategy_class(strategy.args)
