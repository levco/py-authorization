from dataclasses import dataclass


@dataclass
class CheckResponse:
    resource: str
    action: str
    sub_action: str = None
    info: str = None
    allowed: bool = False
    origin: str = False
