from dataclasses import dataclass
from typing import Any, Optional


@dataclass
class Strategy:
    name: str
    args: Optional[dict[str, Any]] = None


@dataclass
class Policy:
    name: str
    resources: list[str]
    roles: list[str]
    actions: list[str]
    sub_action: Optional[str] = None
    strategies: Optional[list[Strategy]] = None
    deny: bool = False
    last_rule: bool = False
