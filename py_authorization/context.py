from dataclasses import dataclass, field
from typing import Any, Optional

from py_authorization.policy import Policy


@dataclass
class Context:
    user_role: str
    policy: Policy
    resource: str
    action: Optional[str] = None
    sub_action: Optional[str] = None
    args: dict[str, Any] = field(default_factory=dict)
