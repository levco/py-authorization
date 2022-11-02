from dataclasses import dataclass
from typing import List

from models.strategy import Strategy


@dataclass
class Policy:
    name: str
    resources: List[str]
    roles: List[str]
    actions: List[str]
    origin: List[str] = None
    sub_action: str = None
    strategies: List[Strategy] = None
    deny: bool = False
    last_rule: bool = False
