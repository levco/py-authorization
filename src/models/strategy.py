from dataclasses import dataclass
from typing import Dict


@dataclass
class Strategy:
    name: str
    args: Dict = None
