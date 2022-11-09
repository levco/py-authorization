import logging
from dataclasses import dataclass
from typing import Any, Optional, TypedDict, TypeVar

from sqlalchemy import inspect
from sqlalchemy.orm.query import Query

from .context import Context
from .policy import Policy, Strategy
from .policy_strategy_builder import PolicyStrategyBuilder, StrategyMapper
from .sql_parser import all_entities_in_statement

T = TypeVar("T", bound=object)


class _ApplicableStrategies(TypedDict):
    strategies: list[Strategy]
    context: Context


class _EmptyEntity(object):
    """An empty entity is one that is passed as a fake entity to methods that ask for one but the current permission
    check doesn't require an entity to run.
    """

    pass


@dataclass
class CheckResponse:
    resource: str
    action: str
    sub_action: Optional[str] = None
    info: Optional[str] = None
    allowed: bool = False


class Authorization:
    def __init__(
        self,
        policies: list[Policy],
        strategy_mapper: StrategyMapper,
        default_action: str = "read",
    ) -> None:
        self.logger = logging.getLogger(__name__)
        self.default_action = default_action
        self.policies = policies
        self.strategy_builder = PolicyStrategyBuilder(strategy_mapper=strategy_mapper)

    def _get_policy(
        self,
        user_role: str,
        resource_to_access: str,
        action: str,
        sub_action: Optional[str],
    ) -> Optional[Policy]:
        policy: Policy
        for policy in self.policies:

            roles = policy.roles
            resources = [r.lower() for r in policy.resources]
            actions = policy.actions

            if "*" not in actions and action not in actions:
                continue
            if policy.sub_action and sub_action != policy.sub_action:
                continue
            if "*" not in resources and resource_to_access.lower() not in resources:
                continue
            if "*" not in roles and user_role not in roles:
                if policy.last_rule:  # last rule for the policy resources
                    break
                continue

            return policy
        return None

    def get_permissions_info(
        self,
        *,
        user_role: str,
        action: str,
        resource: str,
        sub_action: Optional[str] = None,
    ) -> CheckResponse:
        """
        This method provide info to the FE, it doesnt check strategies.
        """

        info = "Allowed."
        allowed = True
        policy = self._get_policy(
            user_role=user_role,
            resource_to_access=resource,
            action=action,
            sub_action=sub_action,
        )
        if not policy:
            info = "No policy found for this resource."
            allowed = False
        if policy and policy.deny:
            info = "No policy found for this resource."
            allowed = False
        if policy and policy.strategies:
            info = "Allowed but filtered."
            allowed = False

        return CheckResponse(
            allowed=allowed,
            info=info,
            action=action,
            sub_action=sub_action,
            resource=resource,
        )

    def is_allowed(
        self,
        *,
        user_role: str,
        action: str,
        resource: str,
        sub_action: Optional[str] = None,
        args: Optional[dict[str, Any]] = None,
    ) -> bool:
        """
        Checks permissions not entity specific , returns True/False.
        """
        action = action or self.default_action

        policy = self._get_policy(
            user_role=user_role,
            action=action,
            sub_action=sub_action,
            resource_to_access=resource,
        )
        if not policy:
            return False
        if policy.deny:
            return False

        if policy.strategies:
            context = Context(
                user_role=user_role,
                policy=policy,
                resource=resource,
                action=action,
                sub_action=sub_action,
                args=args if args else dict(),
            )
            if not self._apply_strategies_to_entity(
                entity=_EmptyEntity(), strategies=policy.strategies, context=context
            ):
                return False

        return True

    def is_entity_allowed(
        self,
        *,
        user_role: str,
        action: str,
        entity: T,
        resource: str,
        sub_action: Optional[str] = None,
        args: Optional[dict[str, Any]] = None,
    ) -> bool:
        """
        Checks a specific entity against the policies rules and returns True/False
        """
        resp = self.apply_policies_to_one(
            user_role=user_role,
            entity=entity,
            resource_to_check=resource,
            action=action,
            sub_action=sub_action,
            args=args,
        )
        return True if resp else False

    def apply_policies_to_many(
        self,
        *,
        user_role: str,
        entities: list[T],
        action: Optional[str] = None,
        sub_action: Optional[str] = None,
        resource_to_check: Optional[str] = None,
        args: Optional[dict[str, Any]] = None,
    ) -> list[T]:
        """
        Applies policies to multiple entities and returns a list of entities allowed
        """
        resp: list[T] = []
        args = args or dict()
        action = action or self.default_action
        if not entities:
            return resp

        if isinstance(entities, Query):
            entities = entities.all()

        for entity in entities:
            valid_entity = self.apply_policies_to_one(
                user_role=user_role,
                action=action,
                sub_action=sub_action,
                entity=entity,
                resource_to_check=resource_to_check,
                args=args,
            )
            if valid_entity:
                resp.append(valid_entity)
        return resp

    def apply_policies_to_one(
        self,
        *,
        user_role: str,
        entity: Optional[T],
        action: Optional[str] = None,
        sub_action: Optional[str] = None,
        resource_to_check: Optional[str] = None,
        args: Optional[dict[str, Any]] = None,
    ) -> Optional[T]:
        """
        Applies policies to one entity and return the entity if its allowed
        """
        self.logger.debug(f"Apply policies to ONE: {entity}")
        if not entity:
            return None
        action = action or self.default_action

        resource_to_access: str = resource_to_check or ""
        if not resource_to_check:
            model = inspect(entity).class_
            resource_to_access = model.__name__

        policy = self._get_policy(
            user_role=user_role,
            resource_to_access=resource_to_access,
            action=action,
            sub_action=sub_action,
        )

        if not policy:
            self.logger.debug(f"[x] Policy not found, resource: '{resource_to_access}'")
            return None

        self.logger.debug(f"Policy applied: {policy}")

        if policy.deny:
            self.logger.debug(
                f"[x] Resource denied by: {policy}, resource: '{resource_to_access}'"
            )
            return None

        if not policy.strategies:
            return entity

        context = Context(
            user_role=user_role,
            policy=policy,
            resource=resource_to_access,
            action=action,
            sub_action=sub_action,
            args=args if args else dict(),
        )
        return self._apply_strategies_to_entity(entity, policy.strategies, context)

    def apply_policies_to_query(
        self,
        *,
        user_role: str,
        query: Query,
        action: Optional[str] = None,
        sub_action: Optional[str] = None,
        resources_to_check: Optional[list[str]] = None,
        args: Optional[dict[str, Any]] = None,
    ) -> Query:
        """
        Applies policies to a query , in case of have an strategy, it applies the strategy filtering the query
        It always returns a sqlalchemy query , in case of no access it return a query that result in no data

        """
        self.logger.debug("Apply policies to QUERY")
        args = args or dict()
        action = action or self.default_action
        strategies_to_apply: list[_ApplicableStrategies] = []

        if not resources_to_check:
            entities = all_entities_in_statement(query)
            resources_to_check = entities.keys() or []

        self.logger.debug("Resources from queries")
        self.logger.debug(resources_to_check)

        self.logger.debug(f"Entities to look for policies: {resources_to_check}")
        for resource_to_access in resources_to_check:
            self.logger.debug(f"Checking Resource: '{resource_to_access}'")
            policy = self._get_policy(
                user_role=user_role,
                resource_to_access=resource_to_access,
                action=action,
                sub_action=sub_action,
            )
            if not policy:
                self.logger.debug(
                    f"[x] Policy not found, resource: '{resource_to_access}'"
                )
                return query.filter(False)

            self.logger.debug(f"Policy applied: {policy}")

            if policy.deny:
                self.logger.debug(
                    f"[x] Resource denied by {policy}, resource: '{resource_to_access}'"
                )
                return query.filter(False)

            if policy.strategies:
                context = Context(
                    user_role=user_role,
                    policy=policy,
                    resource=resource_to_access,
                    action=action,
                    sub_action=sub_action,
                    args=args,
                )
                strategies_to_apply.append(
                    dict(strategies=policy.strategies, context=context)
                )
        if not strategies_to_apply:
            return query

        for to_apply in strategies_to_apply:
            query = self._apply_strategies_to_query(
                query, to_apply["strategies"], to_apply["context"]
            )
        return query

    def _apply_strategies_to_entity(
        self, entity: Optional[T], strategies: list[Strategy], context: Context
    ) -> Optional[T]:
        for strategy in strategies:
            strategy_instance = self.strategy_builder.build(strategy)
            if not strategy_instance:
                return None
            entity = strategy_instance.apply_policies_to_entity(entity, context)
        return entity

    def _apply_strategies_to_query(
        self, query: Query, strategies: list[Strategy], context: Context
    ) -> Query:
        for strategy in strategies:
            strategy_instance = self.strategy_builder.build(strategy)
            if not strategy_instance:
                return query.filter(False)
            query = strategy_instance.apply_policies_to_query(query, context)
        return query
