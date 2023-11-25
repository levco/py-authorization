"""Easily manage authorization complex logic"""

__version__ = "1.6.0"

from .authorization import Authorization, CheckResponse
from .context import Context
from .policy import Policy, Strategy
from .policy_strategy import EmptyEntity, PolicyStrategy
from .policy_strategy_builder import PolicyStrategyBuilder, StrategyMapper
from .user import User

__all__ = [
    "Authorization",
    "CheckResponse",
    "Context",
    "EmptyEntity",
    "Policy",
    "Strategy",
    "PolicyStrategy",
    "PolicyStrategyBuilder",
    "StrategyMapper",
    "User",
]
