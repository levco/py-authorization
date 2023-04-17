from dataclasses import dataclass
from typing import Any, Optional


@dataclass
class User:
    role: str
    id: Optional[Any]
