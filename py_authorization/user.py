from dataclasses import dataclass
from typing import Any, Optional


@dataclass
class User:
    id: Optional[Any]
    role: str
