from dataclasses import dataclass
from typing import Any, Optional

from py_authorization.policy import Policy
from py_authorization.user import User


@dataclass
class Context:
    user: User
    policy: Policy
    resource: str
    args: dict[str, Any]
    action: Optional[str] = None
    sub_action: Optional[str] = None
