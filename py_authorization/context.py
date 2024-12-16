from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Generic, Optional, TypeVar

from py_authorization.policy import Policy
from py_authorization.user import User

T = TypeVar("T", bound=object)
EnumHashKey = TypeVar("EnumHashKey", bound=Enum)


@dataclass
class Cache(Generic[EnumHashKey]):
    cache: dict[EnumHashKey, dict[Any, Any]] = field(default_factory=dict)

    def get(
        self,
        hash_key: EnumHashKey,
        key: tuple[Any, ...],
        return_type: type[T] | None = None,
    ) -> T | None:
        return self.cache.get(hash_key, {}).get(key)

    def set(self, hash_key: EnumHashKey, key: tuple[Any, ...], value: T) -> None:
        self.cache[hash_key] = self.cache.get(hash_key, {})
        self.cache[hash_key][key] = value

    def get_or_set(
        self,
        hash_key: EnumHashKey,
        key: tuple[Any, ...],
        function_for_value: Callable[..., T | None],
    ) -> T | None:
        value = self.get(hash_key, key)
        if value is None:
            value = function_for_value(*key)
            if value:
                self.set(hash_key, key, value)
        return value


@dataclass
class Context(Generic[EnumHashKey]):
    user: User
    policy: Policy
    resource: str
    args: dict[str, Any]
    cache: Cache[EnumHashKey]
    action: Optional[str] = None
    sub_action: Optional[str] = None
