from dataclasses import dataclass
from typing import Any, Optional

from py_authorization.policy import Policy


@dataclass
class Context:
    user_role: str
    policy: Policy
    resource: str
    action: Optional[str] = None
    sub_action: Optional[str] = None
    args: Optional[dict[str, Any]] = None
    attribute_name: Optional[str] = None
