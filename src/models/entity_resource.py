from dataclasses import dataclass
from typing import Dict


@dataclass
class EntityResource:
    resource: str
    entity: object
    args: Dict = None
