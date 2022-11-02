from dataclasses import dataclass
from typing import Dict

from .policy import Policy


@dataclass
class Context:
    user: object
    policy: Policy
    resource: str
    action: str = None
    sub_action: str = None
    args: Dict = None
    attribute_name: str = None
    origin: str = None
