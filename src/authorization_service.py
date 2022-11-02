import logging
from typing import Dict, List, Optional

from sqlalchemy import inspect
from sqlalchemy.orm.query import Query

from src.models.check_response import CheckResponse
from src.models.context import Context
from src.models.policy import Policy
from src.sql_parser import all_entities_in_statement
from src.strategies.policy_strategy_builder import PolicyStrategyBuilder

logger = logging.getLogger(__name__)


class AuthorizationService:
    def __init__(
        self,
        policies: List[Policy],
        strategies_mapper,
        default_action: str = "read",
    ):
        self.default_action = default_action
        self.policies = policies
        self.strategy_builder = PolicyStrategyBuilder(strategies_mapper=strategies_mapper)

    def _log(self, message):
        logger.debug(message)
        # print(f"------------- {message}")  # to use locally , easier to see

    def _get_policy(
        self,
        origin: Optional[str],
        user_role: str,
        resource_to_access: str,
        action: str,
        sub_action: Optional[str],
    ):
        policy: Policy
        for policy in self.policies:

            roles = policy.roles
            resources = [r.lower() for r in policy.resources]
            actions = policy.actions

            if policy.origin and "*" not in policy.origin and origin not in policy.origin:
                continue
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
        return

    def get_permissions_info(
        self, *, user, action: str, resource, sub_action: Optional[str] = None, origin: Optional[str] = None
    ):
        """
        This method provide info to the FE, it doesnt check strategies.
        """

        info = "Allowed."
        allowed = True
        policy = self._get_policy(
            origin=origin, user_role=user.role, resource_to_access=resource, action=action, sub_action=sub_action
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
            origin=origin,
            allowed=allowed,
            info=info,
            action=action,
            sub_action=sub_action,
            resource=resource,
        )

    def is_allowed(
        self,
        *,
        user,
        action: str,
        resource,
        sub_action: Optional[str] = None,
        args: Optional[Dict] = None,
        origin: Optional[str] = None,
    ):
        """
        checks permissions not entity specific , returns True/False
        """
        return self.is_entity_allowed(
            user=user,
            action=action,
            entity=True,
            resource=resource,
            sub_action=sub_action,
            args=args,
            origin=origin,
        )

    def is_entity_allowed(
        self,
        *,
        user,
        action: str,
        entity,
        resource,
        sub_action: Optional[str] = None,
        args: Optional[Dict] = None,
        origin: Optional[str] = None,
    ):
        """
        Checks a specific entity against the policies rules and returns True/False
        """
        resp = self.apply_policies_to_one(
            origin=origin,
            user=user,
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
        user,
        entities,
        action: Optional[str] = None,
        sub_action: Optional[str] = None,
        resource_to_check: Optional[str] = None,
        args: Optional[Dict] = None,
        origin: Optional[str] = None,
    ):
        """
        Applies policies to multiple entities and returns a list of entities allowed
        """
        resp: list = []
        args = args or dict()
        action = action or self.default_action
        if not entities:
            return resp

        if isinstance(entities, Query):
            entities = entities.all()

        for entity in entities:
            valid_entity = self.apply_policies_to_one(
                origin=origin,
                user=user,
                action=action,
                sub_action=sub_action,
                entity=entity,
                resource_to_check=resource_to_check,
                args=args,
            )
            if valid_entity:
                resp.append(valid_entity)
        return resp

    def apply_policies_to_attribute(
        self,
        *,
        user,
        entity,
        resource_to_check: str,
        attribute_name: str,
        action: Optional[str] = None,
        sub_action: Optional[str] = None,
        args: Optional[Dict] = None,
        origin: Optional[str] = None,
    ):
        """
        Checks an entity attribute, this is helpful to block individual properties in a Node
        """
        return self.apply_policies_to_one(
            user=user,
            entity=entity,
            action=action,
            sub_action=sub_action,
            resource_to_check=resource_to_check,
            attribute_name=attribute_name,
            args=args,
            origin=origin,
        )

    def apply_policies_to_one(
        self,
        *,
        user,
        entity,
        action: Optional[str] = None,
        sub_action: Optional[str] = None,
        resource_to_check: Optional[str] = None,
        attribute_name=None,
        args: Optional[Dict] = None,
        origin: Optional[str] = None,
    ):
        """
        Applies policies to one entity and return the entity if its allowed
        """
        self._log(f"Apply policies to ONE: {entity}")
        if not entity:
            return
        args = args or dict()
        action = action or self.default_action

        resource_to_access: str = resource_to_check or ""
        if not resource_to_check:
            model = inspect(entity).class_
            resource_to_access = model.__name__

        policy = self._get_policy(
            origin=origin,
            user_role=user.role,
            resource_to_access=resource_to_access,
            action=action,
            sub_action=sub_action,
        )

        if not policy:
            self._log(f"[x] Policy not found, resource: '{resource_to_access}'")
            return

        self._log(f"Policy applied: {policy}")

        if policy.deny:
            self._log(f"[x] Resource denied by: {policy}, resource: '{resource_to_access}'")
            return

        if not policy.strategies:
            if attribute_name:
                return getattr(entity, attribute_name)
            return entity

        context = Context(
            origin=origin,
            user=user,
            policy=policy,
            resource=resource_to_access,
            action=action,
            sub_action=sub_action,
            args=args,
            attribute_name=attribute_name,
        )
        for strategy in policy.strategies:
            strategy_instance = self.strategy_builder.build(strategy)
            if not strategy_instance:
                self._log("Rejected")
                return
            entity = strategy_instance.apply_policies_to_entity(entity, context)
            self._log("Approved") if entity else self._log("Rejected")

        return entity

    def apply_policies_to_query(
        self,
        *,
        user,
        query: Query,
        action: Optional[str] = None,
        sub_action: Optional[str] = None,
        resources_to_check: Optional[list[str]] = None,
        args: Optional[Dict] = None,
        origin: Optional[str] = None,
    ):
        """
        Applies policies to a query , in case of have an strategy, it applies the strategy filtering the query
        It always returns a sqlalchemy query , in case of no access it return a query that result in no data

        """
        self._log("Apply policies to QUERY")
        if not query:
            return
        args = args or dict()
        action = action or self.default_action
        strategies_to_apply = []

        if not resources_to_check:
            entities = all_entities_in_statement(query)
            resources_to_check = entities.keys() or []

        self._log("Resources from queries")
        self._log(resources_to_check)

        self._log(f"Entities to look for policies: {resources_to_check}")
        for resource_to_access in resources_to_check:
            self._log(f"Checking Resource: '{resource_to_access}'")
            policy = self._get_policy(
                origin=origin,
                user_role=user.role,
                resource_to_access=resource_to_access,
                action=action,
                sub_action=sub_action,
            )
            if not policy:
                self._log(f"[x] Policy not found, resource: '{resource_to_access}'")
                return query.filter(1 == 0)

            self._log(f"Policy applied: {policy}")

            if policy.deny:
                self._log(f"[x] Resource denied by {policy}, resource: '{resource_to_access}'")
                return query.filter(1 == 0)

            if policy.strategies:
                context = Context(
                    origin=origin,
                    user=user,
                    policy=policy,
                    resource=resource_to_access,
                    action=action,
                    sub_action=sub_action,
                    args=args,
                )
                strategies_to_apply.append(dict(strategies=policy.strategies, context=context))
        if not strategies_to_apply:
            return query
        self._log("Applying strategies")
        for to_apply in strategies_to_apply:
            for strategy in to_apply.get("strategies", []):
                self._log(f"Strategy: {strategy}")
                strategy_instance = self.strategy_builder.build(strategy)
                if not strategy_instance:
                    return query.filter(1 == 0)
                query = strategy_instance.apply_policies_to_query(query, to_apply.get("context"))

        return query
