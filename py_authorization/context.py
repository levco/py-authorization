from dataclasses import dataclass
from typing import Any, Optional

from py_authorization.policy import Policy


@dataclass
class Context:
    user_role: str
    policy: Policy
    resource: str
    args: dict[str, Any]
    action: Optional[str] = None
    sub_action: Optional[str] = None
